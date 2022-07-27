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

#include "tink/prf/hkdf_prf_key_manager.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/prf/hkdf_streaming_prf.h"
#include "tink/subtle/prf/prf_set_util.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HkdfPrfKey;
using ::google::crypto::tink::HkdfPrfKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::SizeIs;

TEST(HkdfPrfKeyManagerTest, Basics) {
  EXPECT_THAT(HkdfPrfKeyManager().get_version(), Eq(0));
  EXPECT_THAT(HkdfPrfKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.HkdfPrfKey"));
  EXPECT_THAT(HkdfPrfKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(HkdfPrfKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKey(HkdfPrfKey()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HkdfPrfKeyManagerTest, ValidateValid32ByteKey) {
  HkdfPrfKey key;
  key.set_version(0);
  key.set_key_value("01234567890123456789012345678901");
  key.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKey(key), IsOk());
}

TEST(HkdfPrfKeyManagerTest, ValidateValidSha512Key) {
  HkdfPrfKey key;
  key.set_version(0);
  key.set_key_value("01234567890123456789012345678901");
  key.mutable_params()->set_hash(::google::crypto::tink::SHA512);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKey(key), IsOk());
}

TEST(HkdfPrfKeyManagerTest, ValidateValid33ByteKey) {
  HkdfPrfKey key;
  key.set_version(0);
  key.set_key_value("012345678901234567890123456789012");
  key.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKey(key), IsOk());
}

TEST(HkdfPrfKeyManagerTest, ValidateValidKeyWithSalt) {
  HkdfPrfKey key;
  key.set_version(0);
  key.set_key_value("01234567890123456789012345678901");
  key.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  key.mutable_params()->set_salt("12345");
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKey(key), IsOk());
}

TEST(HkdfPrfKeyManagerTest, InvalidKeySizes31Bytes) {
  HkdfPrfKey key;
  key.set_version(0);
  key.set_key_value("0123456789012345678901234567890");
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HkdfPrfKeyManagerTest, InvalidKeySha1) {
  HkdfPrfKey key;
  key.set_version(0);
  key.set_key_value("01234567890123456789012345678901");
  key.mutable_params()->set_hash(::google::crypto::tink::SHA1);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HkdfPrfKeyManagerTest, InvalidKeyVersion) {
  HkdfPrfKey key;
  key.set_version(1);
  key.set_key_value("01234567890123456789012345678901");
  key.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HkdfPrfKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(HkdfPrfKeyFormat()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HkdfPrfKeyManagerTest, ValidateValid32ByteKeyFormat) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(HkdfPrfKeyManagerTest, ValidateValidSha512KeyFormat) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA512);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(HkdfPrfKeyManagerTest, ValidateValid33ByteKeyFormat) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(33);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(HkdfPrfKeyManagerTest, ValidateValidKeyFormatWithSalt) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  key_format.mutable_params()->set_salt("abcdef");
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(HkdfPrfKeyManagerTest, InvalidKeyFormatSha1) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA1);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HkdfPrfKeyManagerTest, ValidateInvalid31ByteKeyFormat) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(31);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HkdfPrfKeyManagerTest, CreateKey) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  auto key_or = HkdfPrfKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(), SizeIs(32));
  EXPECT_THAT(key_or.value().params().hash(),
              Eq(::google::crypto::tink::SHA256));
  EXPECT_THAT(key_or.value().params().salt(), Eq(""));
  EXPECT_THAT(key_or.value().version(), Eq(0));
}

TEST(HkdfPrfKeyManagerTest, CreateKeyDifferetSize) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(77);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  auto key_or = HkdfPrfKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(), SizeIs(77));
}

TEST(HkdfPrfKeyManagerTest, CreateKeyDifferetHash) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA512);
  auto key_or = HkdfPrfKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().params().hash(),
              Eq(::google::crypto::tink::SHA512));
}

TEST(HkdfPrfKeyManagerTest, CreateKeyDifferetSalt) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA512);
  key_format.mutable_params()->set_salt("saltstring");
  auto key_or = HkdfPrfKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().params().salt(), Eq("saltstring"));
}

TEST(HkdfPrfKeyManagerTest, CreatePrf) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  key_format.mutable_params()->set_salt("salt string");
  auto key_or = HkdfPrfKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());

  StatusOr<std::unique_ptr<StreamingPrf>> prf_or =
      HkdfPrfKeyManager().GetPrimitive<StreamingPrf>(key_or.value());

  ASSERT_THAT(prf_or, IsOk());

  StatusOr<std::unique_ptr<StreamingPrf>> direct_prf =
      subtle::HkdfStreamingPrf::New(
          subtle::SHA256,
          util::SecretDataFromStringView(key_or.value().key_value()),
          "salt string");

  ASSERT_THAT(direct_prf, IsOk());

  std::unique_ptr<InputStream> input =
      prf_or.value()->ComputePrf("input string");
  std::unique_ptr<InputStream> direct_input =
      direct_prf.value()->ComputePrf("input string");

  auto output_or = ReadBytesFromStream(100, input.get());
  auto direct_output_or = ReadBytesFromStream(100, direct_input.get());

  ASSERT_THAT(output_or, IsOk());
  ASSERT_THAT(direct_output_or, IsOk());
  EXPECT_THAT(output_or.value(), Eq(direct_output_or.value()));
}

TEST(HkdfPrfKeyManagerTest, DeriveKey) {
  HkdfPrfKeyFormat format;
  format.set_key_size(32);
  format.set_version(0);
  format.mutable_params()->set_hash(::google::crypto::tink::SHA256);

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  StatusOr<HkdfPrfKey> key_or =
      HkdfPrfKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(),
              Eq("0123456789abcdef0123456789abcdef"));
  EXPECT_THAT(key_or.value().params().hash(), Eq(format.params().hash()));
}

TEST(HmacPrfKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  HkdfPrfKeyFormat format;
  format.set_key_size(32);
  format.set_version(0);
  format.mutable_params()->set_hash(::google::crypto::tink::SHA256);

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef")};

  ASSERT_THAT(HkdfPrfKeyManager().DeriveKey(format, &input_stream).status(),
              Not(IsOk()));
}

TEST(HmacPrfKeyManagerTest, DeriveKeyWrongVersion) {
  HkdfPrfKeyFormat format;
  format.set_key_size(32);
  format.set_version(1);
  format.mutable_params()->set_hash(::google::crypto::tink::SHA256);

  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  ASSERT_THAT(
      HkdfPrfKeyManager().DeriveKey(format, &input_stream).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("version")));
}

TEST(HkdfPrfKeyManagerTest, CreatePrfSet) {
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(::google::crypto::tink::SHA256);
  key_format.mutable_params()->set_salt("salt string");
  auto key_or = HkdfPrfKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());

  StatusOr<std::unique_ptr<Prf>> prf_or =
      HkdfPrfKeyManager().GetPrimitive<Prf>(key_or.value());

  ASSERT_THAT(prf_or, IsOk());

  StatusOr<std::unique_ptr<StreamingPrf>> direct_streaming_prf =
      subtle::HkdfStreamingPrf::New(
          subtle::SHA256,
          util::SecretDataFromStringView(key_or.value().key_value()),
          "salt string");

  ASSERT_THAT(direct_streaming_prf, IsOk());
  auto direct_prf = subtle::CreatePrfFromStreamingPrf(
      std::move(direct_streaming_prf.value()));

  util::StatusOr<std::string> output_or =
      prf_or.value()->Compute("input string", 100);
  util::StatusOr<std::string> direct_output_or =
      direct_prf->Compute("input string", 100);

  ASSERT_THAT(output_or, IsOk());
  ASSERT_THAT(direct_output_or, IsOk());
  EXPECT_THAT(output_or.value(), Eq(direct_output_or.value()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
