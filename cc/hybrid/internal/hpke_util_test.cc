// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/hybrid/internal/hpke_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/util/test_matchers.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::Values;

struct HpkeParamsConversionTestCase {
  google::crypto::tink::HpkeParams input;
  HpkeParams expected;
};

using HpkeParamsConversionTest =
    testing::TestWithParam<HpkeParamsConversionTestCase>;

INSTANTIATE_TEST_SUITE_P(
    HpkeParamsConversionTestSuite, HpkeParamsConversionTest,
    Values(
        HpkeParamsConversionTestCase{
            CreateHpkeParams(google::crypto::tink::DHKEM_X25519_HKDF_SHA256,
                             google::crypto::tink::HKDF_SHA256,
                             google::crypto::tink::AES_128_GCM),
            HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                       HpkeAead::kAes128Gcm}},
        HpkeParamsConversionTestCase{
            CreateHpkeParams(google::crypto::tink::DHKEM_X25519_HKDF_SHA256,
                             google::crypto::tink::HKDF_SHA256,
                             google::crypto::tink::AES_256_GCM),
            HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                       HpkeAead::kAes256Gcm}},
        HpkeParamsConversionTestCase{
            CreateHpkeParams(google::crypto::tink::DHKEM_X25519_HKDF_SHA256,
                             google::crypto::tink::HKDF_SHA256,
                             google::crypto::tink::CHACHA20_POLY1305),
            HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                       HpkeAead::kChaCha20Poly1305}}));

TEST_P(HpkeParamsConversionTest, HpkeParamsProtoToStruct) {
  HpkeParamsConversionTestCase test_case = GetParam();
  util::StatusOr<HpkeParams> params = HpkeParamsProtoToStruct(test_case.input);
  ASSERT_THAT(params, IsOk());

  EXPECT_THAT(params->kem, Eq(test_case.expected.kem));
  EXPECT_THAT(params->kdf, Eq(test_case.expected.kdf));
  EXPECT_THAT(params->aead, Eq(test_case.expected.aead));
}

using HpkeBadParamsTest =
    testing::TestWithParam<google::crypto::tink::HpkeParams>;

INSTANTIATE_TEST_SUITE_P(
    HpkeBadParamsTestSuite, HpkeBadParamsTest,
    Values(CreateHpkeParams(google::crypto::tink::KEM_UNKNOWN,
                            google::crypto::tink::HKDF_SHA256,
                            google::crypto::tink::AES_128_GCM),
           CreateHpkeParams(google::crypto::tink::DHKEM_X25519_HKDF_SHA256,
                            google::crypto::tink::KDF_UNKNOWN,
                            google::crypto::tink::AES_256_GCM),
           CreateHpkeParams(google::crypto::tink::DHKEM_X25519_HKDF_SHA256,
                            google::crypto::tink::HKDF_SHA256,
                            google::crypto::tink::AEAD_UNKNOWN)));

TEST_P(HpkeBadParamsTest, HpkeParamsProtoToStruct) {
  google::crypto::tink::HpkeParams params = GetParam();
  EXPECT_THAT(HpkeParamsProtoToStruct(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeKemEncodingSizeTest, HpkeEncapsulatedKeyLength) {
  // Encapsulated key length should match 'Nenc' column from
  // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
  EXPECT_THAT(
      HpkeEncapsulatedKeyLength(google::crypto::tink::DHKEM_X25519_HKDF_SHA256),
      IsOkAndHolds(32));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
