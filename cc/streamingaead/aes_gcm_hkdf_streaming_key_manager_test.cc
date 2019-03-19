// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"

#include <sstream>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "gtest/gtest.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::AesGcmHkdfStreamingKey;
using google::crypto::tink::AesGcmHkdfStreamingKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;

namespace {

static const char* kKeyTypePrefix = "type.googleapis.com/";
static const char* kAesGcmHkdfStreamingKeyType =
    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

void TestEncryptAndDecrypt(StreamingAead* streaming_aead,
                           int pt_size, absl::string_view associated_data) {
  // Prepare ciphertext destination stream.
  auto ct_stream = absl::make_unique<std::stringstream>();
  // A reference to the ciphertext buffer, for later validation.
  auto ct_buf = ct_stream->rdbuf();
  std::unique_ptr<OutputStream> ct_destination(
      absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));

  // Use streaming_aead to encrypt some data.
  auto enc_stream_result = streaming_aead->NewEncryptingStream(
      std::move(ct_destination), associated_data);
  EXPECT_TRUE(enc_stream_result.ok()) << enc_stream_result.status();
  auto enc_stream = std::move(enc_stream_result.ValueOrDie());
  std::string pt = subtle::Random::GetRandomBytes(pt_size);
  auto status = subtle::test::WriteToStream(enc_stream.get(), pt);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(pt_size, enc_stream->Position());
  std::string ct = ct_buf->str();
  EXPECT_NE(ct, pt);

  // Use AesGcmHkdfStreaming to decrypt the resulting ciphertext.
  auto ct_bytes = absl::make_unique<std::stringstream>(std::string(ct));
  std::unique_ptr<InputStream> ct_source(
      absl::make_unique<util::IstreamInputStream>(std::move(ct_bytes)));
  auto dec_stream_result = streaming_aead->NewDecryptingStream(
      std::move(ct_source), associated_data);
  EXPECT_TRUE(dec_stream_result.ok()) << dec_stream_result.status();
  auto dec_stream = std::move(dec_stream_result.ValueOrDie());
  std::string decrypted;
  status = subtle::test::ReadFromStream(dec_stream.get(), &decrypted);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(pt, decrypted);
}

TEST(AesGcmHkdfStreamingKeyManagerTest, testBasic) {
  AesGcmHkdfStreamingKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST(AesGcmHkdfStreamingKeyManagerTest, testKeyDataErrors) {
  AesGcmHkdfStreamingKeyManager key_manager;

  {  // Bad key type.
    KeyData key_data;
    std::string bad_key_type =
        "type.googleapis.com/google.crypto.tink.SomeOtherKey";
    key_data.set_type_url(bad_key_type);
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, bad_key_type,
                        result.status().error_message());
  }

  {  // Bad key value.
    KeyData key_data;
    key_data.set_type_url(kAesGcmHkdfStreamingKeyType);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    AesGcmHkdfStreamingKey key;
    key.set_version(1);
    key_data.set_type_url(kAesGcmHkdfStreamingKeyType);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }

  {  // Bad derived_key_size (supported sizes: 16, 32).
    for (int derived_key_size = 0; derived_key_size < 42; derived_key_size++) {
      SCOPED_TRACE(absl::StrCat(" derived_key_size = ", derived_key_size));
      AesGcmHkdfStreamingKey key;
      key.set_version(0);
      key.set_key_value(std::string(derived_key_size, 'a'));  // ikm
      key.mutable_params()->set_derived_key_size(derived_key_size);
      key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
      key.mutable_params()->set_ciphertext_segment_size(1024);
      KeyData key_data;
      key_data.set_type_url(kAesGcmHkdfStreamingKeyType);
      key_data.set_value(key.SerializeAsString());
      auto result = key_manager.GetPrimitive(key_data);
      if (derived_key_size == 16 || derived_key_size == 32) {
        EXPECT_TRUE(result.ok()) << result.status();
      } else {
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring,
                            std::to_string(derived_key_size) + " bytes",
                            result.status().error_message());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported sizes",
                            result.status().error_message());
      }
    }
  }
}

TEST(AesGcmHkdfStreamingKeyManagerTest, testKeyMessageErrors) {
  AesGcmHkdfStreamingKeyManager key_manager;

  {  // Bad protobuffer.
    AesEaxKey key;
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesEaxKey",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }

  {  // Bad derived_key_size (supported sizes: 16, 32).
    for (int derived_key_size = 0; derived_key_size < 42; derived_key_size++) {
      SCOPED_TRACE(absl::StrCat(" derived_key_size = ", derived_key_size));
      AesGcmHkdfStreamingKey key;
      key.set_version(0);
      key.set_key_value(std::string(derived_key_size, 'a'));  // ikm
      key.mutable_params()->set_derived_key_size(derived_key_size);
      key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
      key.mutable_params()->set_ciphertext_segment_size(1024);
      auto result = key_manager.GetPrimitive(key);
      if (derived_key_size == 16 || derived_key_size == 32) {
        EXPECT_TRUE(result.ok()) << result.status();
      } else {
          EXPECT_FALSE(result.ok());
          EXPECT_EQ(util::error::INVALID_ARGUMENT,
                    result.status().error_code());
          EXPECT_PRED_FORMAT2(testing::IsSubstring,
                              std::to_string(derived_key_size) + " bytes",
                              result.status().error_message());
          EXPECT_PRED_FORMAT2(testing::IsSubstring, "supported sizes",
                              result.status().error_message());
      }
    }
  }
}

TEST(AesGcmHkdfStreamingKeyManagerTest, testPrimitives) {
  std::string plaintext = "some plaintext";
  std::string aad = "some aad";
  AesGcmHkdfStreamingKeyManager key_manager;
  AesGcmHkdfStreamingKey key;

  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  auto params = key.mutable_params();
  params->set_ciphertext_segment_size(1024);
  params->set_derived_key_size(16);
  params->set_hkdf_hash_type(HashType::SHA256);

  {  // Using key message only.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    TestEncryptAndDecrypt(result.ValueOrDie().get(), 10, "associated data");
    TestEncryptAndDecrypt(result.ValueOrDie().get(), 10000, "also aad");
    TestEncryptAndDecrypt(result.ValueOrDie().get(), 0, "another aad");
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(kAesGcmHkdfStreamingKeyType);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    TestEncryptAndDecrypt(result.ValueOrDie().get(), 10, "associated data2");
    TestEncryptAndDecrypt(result.ValueOrDie().get(), 10000, "also aad2");
    TestEncryptAndDecrypt(result.ValueOrDie().get(), 0, "yet another aad");
  }
}

TEST(AesGcmHkdfStreamingKeyManagerTest, testNewKeyErrors) {
  AesGcmHkdfStreamingKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  {  // Bad key format.
    AesEaxKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesEaxKeyFormat",
                        result.status().error_message());
  }

  {  // Bad serialized key format.
    auto result = key_factory.NewKey("some bad serialized proto");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad AesGcmHkdfStreamingKeyFormat: small key_size.
    AesGcmHkdfStreamingKeyFormat key_format;
    key_format.set_key_size(16);
    key_format.mutable_params()->set_derived_key_size(32);
    key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
    key_format.mutable_params()->set_ciphertext_segment_size(1024);
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "must not be smaller",
                        result.status().error_message());
  }
}

TEST(AesGcmHkdfStreamingKeyManagerTest, testNewKeyBasic) {
  AesGcmHkdfStreamingKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_derived_key_size(16);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA1);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  { // Via NewKey(format_proto).
    auto result = key_factory.NewKey(key_format);
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(std::string(kKeyTypePrefix) + key->GetTypeName(),
              kAesGcmHkdfStreamingKeyType);
    std::unique_ptr<AesGcmHkdfStreamingKey> aes_gcm_hkdf_streaming_key(
        reinterpret_cast<AesGcmHkdfStreamingKey*>(key.release()));
    EXPECT_EQ(0, aes_gcm_hkdf_streaming_key->version());
    EXPECT_EQ(key_format.key_size(),
              aes_gcm_hkdf_streaming_key->key_value().size());
  }

  { // Via NewKey(serialized_format_proto).
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(std::string(kKeyTypePrefix) + key->GetTypeName(),
              kAesGcmHkdfStreamingKeyType);
    std::unique_ptr<AesGcmHkdfStreamingKey> aes_gcm_hkdf_streaming_key(
        reinterpret_cast<AesGcmHkdfStreamingKey*>(key.release()));
    EXPECT_EQ(0, aes_gcm_hkdf_streaming_key->version());
    EXPECT_EQ(key_format.key_size(),
              aes_gcm_hkdf_streaming_key->key_value().size());
  }

  { // Via NewKeyData(serialized_format_proto).
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    auto key_data = std::move(result.ValueOrDie());
    EXPECT_EQ(kAesGcmHkdfStreamingKeyType, key_data->type_url());
    EXPECT_EQ(KeyData::SYMMETRIC, key_data->key_material_type());
    AesGcmHkdfStreamingKey aes_gcm_hkdf_streaming_key;
    EXPECT_TRUE(aes_gcm_hkdf_streaming_key.ParseFromString(key_data->value()));
    EXPECT_EQ(0, aes_gcm_hkdf_streaming_key.version());
    EXPECT_EQ(key_format.key_size(),
              aes_gcm_hkdf_streaming_key.key_value().size());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
