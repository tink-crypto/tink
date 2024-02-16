// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/streaming_aead_wrapper.h"

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/config/global_registry.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/test_random_access_stream.h"
#include "tink/keyset_handle.h"
#include "tink/output_stream.h"
#include "tink/primitive_set.h"
#include "tink/proto_keyset_format.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/streamingaead/streaming_aead_config.h"
#include "tink/subtle/random.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/subtle/test_util.h"
#include "tink/util/buffer.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ReadAllFromRandomAccessStream;
using ::crypto::tink::subtle::test::ReadFromStream;
using ::crypto::tink::subtle::test::WriteToStream;
using ::crypto::tink::test::DummyStreamingAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::HasSubstr;

// A container for specification of instances of DummyStreamingAead
// to be created for testing.
struct StreamingAeadSpec {
  uint32_t key_id;
  std::string saead_name;
  OutputPrefixType output_prefix_type;
};

// Generates a PrimitiveSet<StreamingAead> with DummyStreamingAead
// instances according to the specification in 'spec'.
// The last entry in 'spec' will be the primary primitive in the returned set.
std::unique_ptr<PrimitiveSet<StreamingAead>> GetTestStreamingAeadSet(
    const std::vector<StreamingAeadSpec>& spec) {
  auto saead_set = absl::make_unique<PrimitiveSet<StreamingAead>>();
  int i = 0;
  for (auto& s : spec) {
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(s.output_prefix_type);
    key_info.set_key_id(s.key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::unique_ptr<StreamingAead> saead =
        absl::make_unique<DummyStreamingAead>(s.saead_name);
    auto entry_result = saead_set->AddPrimitive(std::move(saead), key_info);
    EXPECT_TRUE(entry_result.ok());
    if (i + 1 == spec.size()) {
      EXPECT_THAT(saead_set->set_primary(entry_result.value()), IsOk());
    }
    i++;
  }
  return saead_set;
}

TEST(StreamingAeadSetWrapperTest, WrapNullptr) {
  StreamingAeadWrapper wrapper;
  auto result = wrapper.Wrap(nullptr);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInternal, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                      std::string(result.status().message()));
}

TEST(StreamingAeadSetWrapperTest, WrapEmpty) {
  StreamingAeadWrapper wrapper;
  auto result = wrapper.Wrap(absl::make_unique<PrimitiveSet<StreamingAead>>());
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                      std::string(result.status().message()));
}

TEST(StreamingAeadSetWrapperTest, BasicEncryptionAndDecryption) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0, OutputPrefixType::RAW},
       {key_id_1, saead_name_1, OutputPrefixType::RAW},
       {key_id_2, saead_name_2, OutputPrefixType::RAW}});

  // Wrap saead_set and test the resulting StreamingAead.
  StreamingAeadWrapper wrapper;
  auto wrap_result = wrapper.Wrap(std::move(saead_set));
  EXPECT_TRUE(wrap_result.ok()) << wrap_result.status();
  auto saead = std::move(wrap_result.value());
  for (int pt_size : {0, 1, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));

      // Prepare ciphertext destination stream.
      auto ct_stream = absl::make_unique<std::stringstream>();
      // A reference to the ciphertext buffer, for later validation.
      auto ct_buf = ct_stream->rdbuf();
      std::unique_ptr<OutputStream> ct_destination(
          absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));
      // Encrypt the plaintext.
      auto enc_stream_result =
          saead->NewEncryptingStream(std::move(ct_destination), aad);
      EXPECT_THAT(enc_stream_result, IsOk());
      auto enc_stream = std::move(enc_stream_result.value());
      auto status = WriteToStream(enc_stream.get(), plaintext);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(absl::StrCat(saead_name_2, aad, plaintext), ct_buf->str());
      // Prepare ciphertext source stream.
      auto ct_source_stream =
          absl::make_unique<std::stringstream>(ct_buf->str());
      std::unique_ptr<InputStream> ct_source(
          absl::make_unique<util::IstreamInputStream>(
              std::move(ct_source_stream)));
      // Decrypt the ciphertext.
      auto dec_stream_result =
          saead->NewDecryptingStream(std::move(ct_source), aad);
      EXPECT_THAT(dec_stream_result, IsOk());
      std::string decrypted;
      status = ReadFromStream(dec_stream_result.value().get(), &decrypted);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(plaintext, decrypted);
    }
  }
}

TEST(StreamingAeadSetWrapperTest, DecryptionWithRandomAccessStream) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0, OutputPrefixType::RAW},
       {key_id_1, saead_name_1, OutputPrefixType::RAW},
       {key_id_2, saead_name_2, OutputPrefixType::RAW}});

  // Wrap saead_set and test the resulting StreamingAead.
  StreamingAeadWrapper wrapper;
  auto wrap_result = wrapper.Wrap(std::move(saead_set));
  EXPECT_TRUE(wrap_result.ok()) << wrap_result.status();
  auto saead = std::move(wrap_result.value());
  for (int pt_size : {0, 1, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));

      // Prepare ciphertext destination stream.
      auto ct_stream = absl::make_unique<std::stringstream>();
      // A reference to the ciphertext buffer, for later validation.
      auto ct_buf = ct_stream->rdbuf();
      std::unique_ptr<OutputStream> ct_destination(
          absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));

      // Encrypt the plaintext.
      auto enc_stream_result =
          saead->NewEncryptingStream(std::move(ct_destination), aad);
      EXPECT_THAT(enc_stream_result, IsOk());
      auto enc_stream = std::move(enc_stream_result.value());
      auto status = WriteToStream(enc_stream.get(), plaintext);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(absl::StrCat(saead_name_2, aad, plaintext), ct_buf->str());

      // Decrypt the ciphertext.
      auto ct_source =
          std::make_unique<internal::TestRandomAccessStream>(ct_buf->str());
      auto dec_stream_result =
          saead->NewDecryptingRandomAccessStream(std::move(ct_source), aad);
      EXPECT_THAT(dec_stream_result, IsOk());
      std::string decrypted;
      status = internal::ReadAllFromRandomAccessStream(
          dec_stream_result.value().get(), decrypted);
      EXPECT_THAT(status, StatusIs(absl::StatusCode::kOutOfRange,
                                   HasSubstr("EOF")));
      EXPECT_EQ(plaintext, decrypted);
    }
  }
}

TEST(StreamingAeadSetWrapperTest, DecryptionAfterWrapperIsDestroyed) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0, OutputPrefixType::RAW},
       {key_id_1, saead_name_1, OutputPrefixType::RAW},
       {key_id_2, saead_name_2, OutputPrefixType::RAW}});

  int pt_size = 100;
  std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
  std::string aad = "some_aad";
  std::unique_ptr<InputStream> dec_stream;
  {
    // Wrap saead_set and test the resulting StreamingAead.
    StreamingAeadWrapper wrapper;
    auto wrap_result = wrapper.Wrap(std::move(saead_set));
    EXPECT_TRUE(wrap_result.ok()) << wrap_result.status();
    auto saead = std::move(wrap_result.value());

    // Prepare ciphertext destination stream.
    auto ct_stream = absl::make_unique<std::stringstream>();
    // A reference to the ciphertext buffer, for later validation.
    auto ct_buf = ct_stream->rdbuf();
    std::unique_ptr<OutputStream> ct_destination(
        absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));
    // Encrypt the plaintext.
    auto enc_stream_result =
        saead->NewEncryptingStream(std::move(ct_destination), aad);
    EXPECT_THAT(enc_stream_result, IsOk());
    auto enc_stream = std::move(enc_stream_result.value());
    auto status = WriteToStream(enc_stream.get(), plaintext);
    EXPECT_THAT(status, IsOk());
    EXPECT_EQ(absl::StrCat(saead_name_2, aad, plaintext), ct_buf->str());
    // Prepare ciphertext source stream.
    auto ct_source_stream =
        absl::make_unique<std::stringstream>(ct_buf->str());
    std::unique_ptr<InputStream> ct_source(
        absl::make_unique<util::IstreamInputStream>(
            std::move(ct_source_stream)));
    // Decrypt the ciphertext.
    auto dec_stream_result =
        saead->NewDecryptingStream(std::move(ct_source), aad);
    EXPECT_THAT(dec_stream_result, IsOk());
    dec_stream = std::move(dec_stream_result.value());
  }
  // Now wrapper and saead are out of scope,
  // but decrypting stream should still work.
  std::string decrypted;
  auto status = ReadFromStream(dec_stream.get(), &decrypted);
  EXPECT_THAT(status, IsOk());
  EXPECT_EQ(plaintext, decrypted);
}

TEST(StreamingAeadSetWrapperTest, EncryptWithTink) {
  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());

  google::crypto::tink::AesGcmHkdfStreamingKey key;
  key.set_key_value("0123456789012345");
  google::crypto::tink::AesGcmHkdfStreamingParams& params =
      *key.mutable_params();
  params.set_hkdf_hash_type(google::crypto::tink::HashType::SHA1);
  params.set_derived_key_size(16);
  params.set_ciphertext_segment_size(1024);

  std::string serialized_key_1 = key.SerializeAsString();

  key.set_key_value("0123456789abcdef");
  std::string serialized_key_2 = key.SerializeAsString();

  google::crypto::tink::Keyset keyset;
  {
    google::crypto::tink::Keyset::Key& keyset_key = *keyset.add_key();
    google::crypto::tink::KeyData& key_data = *keyset_key.mutable_key_data();
    key_data.set_type_url(AesGcmHkdfStreamingKeyManager().get_key_type());
    key_data.set_value(serialized_key_1);
    key_data.set_key_material_type(google::crypto::tink::KeyData::SYMMETRIC);
    keyset_key.set_key_id(1);
    keyset_key.set_output_prefix_type(
        google::crypto::tink::OutputPrefixType::TINK);
    keyset_key.set_status(google::crypto::tink::KeyStatusType::ENABLED);

    keyset.set_primary_key_id(1);
  }
  {
    google::crypto::tink::Keyset::Key& keyset_key = *keyset.add_key();
    google::crypto::tink::KeyData& key_data = *keyset_key.mutable_key_data();
    key_data.set_type_url(AesGcmHkdfStreamingKeyManager().get_key_type());
    key_data.set_value(serialized_key_2);
    key_data.set_key_material_type(google::crypto::tink::KeyData::SYMMETRIC);
    keyset_key.set_key_id(2);
    keyset_key.set_output_prefix_type(
        google::crypto::tink::OutputPrefixType::RAW);
    keyset_key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  }

  crypto::tink::util::StatusOr<KeysetHandle> handle =
      ParseKeysetFromProtoKeysetFormat(keyset.SerializeAsString(),
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(handle.status(), IsOk());

  crypto::tink::util::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      handle->GetPrimitive<crypto::tink::StreamingAead>(ConfigGlobalRegistry());

  ASSERT_THAT(streaming_aead.status(), IsOk());

  EXPECT_THAT(EncryptThenDecrypt(streaming_aead.value().get(),
                                 streaming_aead.value().get(),
                                 subtle::Random::GetRandomBytes(10000),
                                 "some associated data", 0),
              IsOk());
}

// Tests that we can decrypt with an old key using NewDecryptingStream
TEST(StreamingAeadSetWrapperTest, DecryptOldKeyWorks) {
  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());

  // We use the manually created test vector from
  // aes_gcm_hkdf_streaming_key_test.py
  // on https://github.com/tink-crypto/tink-cross-lang-tests
  google::crypto::tink::AesGcmHkdfStreamingKey key;
  key.set_key_value(absl::HexStringToBytes("6eb56cdc726dfbe5d57f2fcdc6e9345b"));
  google::crypto::tink::AesGcmHkdfStreamingParams& params =
      *key.mutable_params();
  params.set_hkdf_hash_type(google::crypto::tink::HashType::SHA1);
  params.set_derived_key_size(16);
  params.set_ciphertext_segment_size(64);
  std::string key_used_for_ciphertext = key.SerializeAsString();
  // New lines are as in the above test: they split the header and ciphertext
  // blocks
  std::string ciphertext = absl::HexStringToBytes(
      "1893b3af5e14ab378d065addfc8484da642c0862877baea8"
      "db92d9c77406a406168478821c4298eab3e6d531277f4c1a051714f"
      "aebcaefcbca7b7be05e9445ea"
      "a0bb2904153398a25084dd80ae0edcd1c3079fcea2cd3770"
      "630ee36f7539207b8ec9d754956d486b71cdf989f0ed6fba"
      "6779b63558be0a66e668df14e1603cd2"
      "af8944844078345286d0b292e772e7190775"
      "c51a0f83e40c0b75821027e7e538e111");
  std::string associated_data = "aad";

  google::crypto::tink::Keyset keyset;
  {
    // Key 1: a different key with the same parameters, primary
    google::crypto::tink::Keyset::Key& keyset_key = *keyset.add_key();
    google::crypto::tink::KeyData& key_data = *keyset_key.mutable_key_data();
    key_data.set_type_url(AesGcmHkdfStreamingKeyManager().get_key_type());
    key.set_key_value("0123456789012345");
    key_data.set_value(key.SerializeAsString());
    key_data.set_key_material_type(google::crypto::tink::KeyData::SYMMETRIC);
    keyset_key.set_key_id(1);
    keyset_key.set_output_prefix_type(
        google::crypto::tink::OutputPrefixType::TINK);
    keyset_key.set_status(google::crypto::tink::KeyStatusType::ENABLED);

    keyset.set_primary_key_id(1);
  }
  {
    // Key 2: the correct key for our ciphertext
    google::crypto::tink::Keyset::Key& keyset_key = *keyset.add_key();
    google::crypto::tink::KeyData& key_data = *keyset_key.mutable_key_data();
    key_data.set_type_url(AesGcmHkdfStreamingKeyManager().get_key_type());
    key_data.set_value(key_used_for_ciphertext);
    key_data.set_key_material_type(google::crypto::tink::KeyData::SYMMETRIC);
    keyset_key.set_key_id(2);
    keyset_key.set_output_prefix_type(
        google::crypto::tink::OutputPrefixType::TINK);
    keyset_key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  }
  {
    // Key 3: a different key with the same parameters
    google::crypto::tink::Keyset::Key& keyset_key = *keyset.add_key();
    google::crypto::tink::KeyData& key_data = *keyset_key.mutable_key_data();
    key_data.set_type_url(AesGcmHkdfStreamingKeyManager().get_key_type());
    key.set_key_value("abcdefghijklmnop");
    key_data.set_value(key.SerializeAsString());
    key_data.set_key_material_type(google::crypto::tink::KeyData::SYMMETRIC);
    keyset_key.set_key_id(3);
    keyset_key.set_output_prefix_type(
        google::crypto::tink::OutputPrefixType::TINK);
    keyset_key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  }

  util::StatusOr<KeysetHandle> handle = ParseKeysetFromProtoKeysetFormat(
      keyset.SerializeAsString(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(handle.status(), IsOk());

  crypto::tink::util::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      handle->GetPrimitive<crypto::tink::StreamingAead>(ConfigGlobalRegistry());
  ASSERT_THAT(streaming_aead.status(), IsOk());

  auto ciphertext_input_stream = std::make_unique<IstreamInputStream>(
      absl::make_unique<std::istringstream>(ciphertext));
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::InputStream>>
      plaintext_stream =
          (*streaming_aead)
              ->NewDecryptingStream(std::move(ciphertext_input_stream),
                                    associated_data);
  ASSERT_THAT(plaintext_stream.status(), IsOk());
  std::string decrypted;
  ASSERT_THAT(ReadFromStream(plaintext_stream->get(), &decrypted), IsOk());
  EXPECT_EQ(decrypted,
            "This is a fairly long plaintext. It is of the exact length to "
            "create three output blocks. ");
}

// Tests that we can decrypt with an old key and NewDecryptingRandomAccessStream
TEST(StreamingAeadSetWrapperTest, DecryptOldKeyWorksWithRandomAccess) {
  ASSERT_THAT(StreamingAeadConfig::Register(), IsOk());

  // We use the manually created test vector from
  // aes_gcm_hkdf_streaming_key_test.py
  // on https://github.com/tink-crypto/tink-cross-lang-tests
  google::crypto::tink::AesGcmHkdfStreamingKey key;
  key.set_key_value(absl::HexStringToBytes("6eb56cdc726dfbe5d57f2fcdc6e9345b"));
  google::crypto::tink::AesGcmHkdfStreamingParams& params =
      *key.mutable_params();
  params.set_hkdf_hash_type(google::crypto::tink::HashType::SHA1);
  params.set_derived_key_size(16);
  params.set_ciphertext_segment_size(64);
  std::string key_used_for_ciphertext = key.SerializeAsString();
  // New lines are as in the above test: they split the header and ciphertext
  // blocks
  std::string ciphertext = absl::HexStringToBytes(
      "1893b3af5e14ab378d065addfc8484da642c0862877baea8"
      "db92d9c77406a406168478821c4298eab3e6d531277f4c1a051714f"
      "aebcaefcbca7b7be05e9445ea"
      "a0bb2904153398a25084dd80ae0edcd1c3079fcea2cd3770"
      "630ee36f7539207b8ec9d754956d486b71cdf989f0ed6fba"
      "6779b63558be0a66e668df14e1603cd2"
      "af8944844078345286d0b292e772e7190775"
      "c51a0f83e40c0b75821027e7e538e111");
  std::string associated_data = "aad";

  google::crypto::tink::Keyset keyset;
  {
    // Key 1: a different key with the same parameters, primary
    google::crypto::tink::Keyset::Key& keyset_key = *keyset.add_key();
    google::crypto::tink::KeyData& key_data = *keyset_key.mutable_key_data();
    key_data.set_type_url(AesGcmHkdfStreamingKeyManager().get_key_type());
    key.set_key_value("0123456789012345");
    key_data.set_value(key.SerializeAsString());
    key_data.set_key_material_type(google::crypto::tink::KeyData::SYMMETRIC);
    keyset_key.set_key_id(1);
    keyset_key.set_output_prefix_type(
        google::crypto::tink::OutputPrefixType::TINK);
    keyset_key.set_status(google::crypto::tink::KeyStatusType::ENABLED);

    keyset.set_primary_key_id(1);
  }
  {
    // Key 2: the correct key for our ciphertext
    google::crypto::tink::Keyset::Key& keyset_key = *keyset.add_key();
    google::crypto::tink::KeyData& key_data = *keyset_key.mutable_key_data();
    key_data.set_type_url(AesGcmHkdfStreamingKeyManager().get_key_type());
    key_data.set_value(key_used_for_ciphertext);
    key_data.set_key_material_type(google::crypto::tink::KeyData::SYMMETRIC);
    keyset_key.set_key_id(2);
    keyset_key.set_output_prefix_type(
        google::crypto::tink::OutputPrefixType::TINK);
    keyset_key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  }
  {
    // Key 3: a different key with the same parameters
    google::crypto::tink::Keyset::Key& keyset_key = *keyset.add_key();
    google::crypto::tink::KeyData& key_data = *keyset_key.mutable_key_data();
    key_data.set_type_url(AesGcmHkdfStreamingKeyManager().get_key_type());
    key.set_key_value("abcdefghijklmnop");
    key_data.set_value(key.SerializeAsString());
    key_data.set_key_material_type(google::crypto::tink::KeyData::SYMMETRIC);
    keyset_key.set_key_id(3);
    keyset_key.set_output_prefix_type(
        google::crypto::tink::OutputPrefixType::TINK);
    keyset_key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  }

  crypto::tink::util::StatusOr<KeysetHandle> handle =
      ParseKeysetFromProtoKeysetFormat(keyset.SerializeAsString(),
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(handle.status(), IsOk());

  crypto::tink::util::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      handle->GetPrimitive<crypto::tink::StreamingAead>(ConfigGlobalRegistry());
  ASSERT_THAT(streaming_aead.status(), IsOk());

  auto ciphertext_random_access_stream =
      std::make_unique<internal::TestRandomAccessStream>(ciphertext);
  crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::RandomAccessStream>>
      plaintext_stream =
          (*streaming_aead)
              ->NewDecryptingRandomAccessStream(
                  std::move(ciphertext_random_access_stream), associated_data);
  ASSERT_THAT(plaintext_stream.status(), IsOk());
  std::string decrypted;
  ASSERT_THAT(
      ReadAllFromRandomAccessStream(plaintext_stream->get(), decrypted, 100),
      StatusIs(absl::StatusCode::kOutOfRange));
  EXPECT_EQ(decrypted,
            "This is a fairly long plaintext. It is of the exact length to "
            "create three output blocks. ");
}

}  // namespace
}  // namespace tink
}  // namespace crypto
