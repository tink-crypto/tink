// Copyright 2019 Google LLC
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

#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"

#include <sstream>
#include <string>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/aes_ctr_hmac_streaming.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr_hmac_streaming.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCtrHmacStreamingKey;
using ::google::crypto::tink::AesCtrHmacStreamingKeyFormat;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

namespace {

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKey) {
  AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value("0123456789abcdef");
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key), IsOk());
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyDerivedKeySizes) {
  for (int derived_key_size = 0; derived_key_size < 42; derived_key_size++) {
    SCOPED_TRACE(absl::StrCat(" derived_key_size = ", derived_key_size));
    AesCtrHmacStreamingKey key;
    key.set_version(0);
    key.set_key_value(std::string(derived_key_size, 'a'));  // ikm
    key.mutable_params()->set_derived_key_size(derived_key_size);
    key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
    key.mutable_params()->set_ciphertext_segment_size(1024);
    key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
    key.mutable_params()->mutable_hmac_params()->set_tag_size(32);
    if (derived_key_size == 16 || derived_key_size == 32) {
      EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key), IsOk());
    } else {
      EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key),
                  StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyDerivedKeyWrongVersion) {
  AesCtrHmacStreamingKey key;
  key.set_version(1);
  key.set_key_value("0123456789abcdef");
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacStreamingKeyManagerTest, GetPrimitive) {
  std::string plaintext = "some plaintext";
  std::string aad = "some aad";

  AesCtrHmacStreamingKey key;
  key.set_version(0);
  key.set_key_value("16 bytes of key ");
  key.mutable_params()->set_ciphertext_segment_size(1024);
  key.mutable_params()->set_derived_key_size(16);
  key.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);

  auto streaming_aead_from_manager_result =
      AesCtrHmacStreamingKeyManager().GetPrimitive<StreamingAead>(key);
  ASSERT_THAT(streaming_aead_from_manager_result.status(), IsOk());

  subtle::AesCtrHmacStreaming::Params params;
  params.ikm = util::SecretDataFromStringView("16 bytes of key ");
  params.hkdf_algo = subtle::HashType::SHA256;;
  params.key_size = 16;
  params.ciphertext_segment_size = 1024;
  params.ciphertext_offset = 0;
  params.tag_algo = subtle::HashType::SHA256;
  params.tag_size = 32;
  auto streaming_aead_direct_result =
      crypto::tink::subtle::AesCtrHmacStreaming::New(params);
  ASSERT_THAT(streaming_aead_direct_result.status(), IsOk());

  // Check that the two primitives are the same by encrypting with one, and
  // decrypting with the other.
  EXPECT_THAT(
      EncryptThenDecrypt(streaming_aead_from_manager_result.value().get(),
                         streaming_aead_direct_result.value().get(),
                         subtle::Random::GetRandomBytes(10000),
                         "some associated data", params.ciphertext_offset),
      IsOk());
}

TEST(AesCtrHmacStreamingKeyManagerTest, Version) {
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().get_version(), Eq(0));
}

TEST(AesCtrHmacStreamingKeyManagerTest, KeyMaterialType) {
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesCtrHmacStreamingKeyManagerTest, KeyType) {
  EXPECT_THAT(
      AesCtrHmacStreamingKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatEmpty) {
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(
                  AesCtrHmacStreamingKeyFormat()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormat) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatSmallKey) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("derived_key_size")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatWrongHash) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("hkdf_hash_type")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatWrongHmacHash) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("hmac_params.hash")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, ValidateKeyFormatSmallSegment) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(45);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_segment_size")));
}

TEST(AesCtrHmacStreamingKeyManagerTest, CreateKey) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);
  key_format.mutable_params()->mutable_hmac_params()->
      set_hash(HashType::SHA256);
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  auto key_or = AesCtrHmacStreamingKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.value().version(), Eq(0));
  EXPECT_THAT(key_or.value().params().ciphertext_segment_size(),
              Eq(key_format.params().ciphertext_segment_size()));
  EXPECT_THAT(key_or.value().params().derived_key_size(),
              Eq(key_format.params().derived_key_size()));
  EXPECT_THAT(key_or.value().params().hkdf_hash_type(),
              Eq(key_format.params().hkdf_hash_type()));
  EXPECT_THAT(key_or.value().key_value().size(), Eq(key_format.key_size()));
  EXPECT_THAT(key_or.value().params().hmac_params().hash(),
              Eq(key_format.params().hmac_params().hash()));
  EXPECT_THAT(key_or.value().params().hmac_params().tag_size(),
              Eq(key_format.params().hmac_params().tag_size()));
}

TEST(AesCtrHmacStreamingKeyManagerTest, DeriveKey) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("01234567890123456789012345678901")};

  util::StatusOr<AesCtrHmacStreamingKey> key_or =
      AesCtrHmacStreamingKeyManager().DeriveKey(key_format, &input_stream);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.value().key_value(),
              Eq("01234567890123456789012345678901"));
  EXPECT_THAT(key_or.value().params().derived_key_size(),
              Eq(key_format.params().derived_key_size()));
  EXPECT_THAT(key_or.value().params().hkdf_hash_type(),
              Eq(key_format.params().hkdf_hash_type()));
  EXPECT_THAT(key_or.value().params().ciphertext_segment_size(),
              Eq(key_format.params().ciphertext_segment_size()));
}

TEST(AesCtrHmacStreamingKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789012345678901234567890")};

  ASSERT_THAT(AesCtrHmacStreamingKeyManager()
                  .DeriveKey(key_format, &input_stream)
                  .status(),
              Not(IsOk()));
}

TEST(AesCtrHmacStreamingKeyManagerTest, DeriveKeyWrongVersion) {
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_version(1);
  key_format.set_key_size(32);
  key_format.mutable_params()->set_derived_key_size(32);
  key_format.mutable_params()->set_hkdf_hash_type(HashType::SHA256);
  key_format.mutable_params()->set_ciphertext_segment_size(1024);

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef")};

  ASSERT_THAT(
      AesCtrHmacStreamingKeyManager()
          .DeriveKey(key_format, &input_stream)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("version")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
