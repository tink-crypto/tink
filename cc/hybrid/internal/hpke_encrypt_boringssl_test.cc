// Copyright 2021 Google LLC
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

#include "tink/hybrid/internal/hpke_encrypt_boringssl.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using ::testing::Values;

class HpkeEncapsulateKeyThenEncryptBoringSslTest
    : public testing::TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeEncapsulateKeyThenEncryptBoringSslTestSuite,
    HpkeEncapsulateKeyThenEncryptBoringSslTest,
    Values(CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256,
                            HpkeAead::CHACHA20_POLY1305)));

TEST_P(HpkeEncapsulateKeyThenEncryptBoringSslTest, EncapsulateKeyThenEncrypt) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params, IsOk());
  util::StatusOr<std::unique_ptr<HpkeEncryptBoringSsl>> hpke_encrypt =
      HpkeEncryptBoringSsl::NewForTesting(
          hpke_params, params->recipient_public_key, params->application_info,
          params->seed_for_testing);
  ASSERT_THAT(hpke_encrypt, IsOk());
  util::StatusOr<std::string> ciphertext =
      (*hpke_encrypt)
          ->EncapsulateKeyThenEncrypt(params->plaintext,
                                      params->associated_data);
  ASSERT_THAT(ciphertext, IsOkAndHolds(absl::StrCat(params->encapsulated_key,
                                                    params->ciphertext)));
}

class HpkeEncryptBoringSslWithBadParamTest
    : public testing::TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeEncryptionBoringSslWithBadParamTestSuite,
    HpkeEncryptBoringSslWithBadParamTest,
    Values(CreateHpkeParams(HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::KDF_UNKNOWN, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AEAD_UNKNOWN)));

TEST_P(HpkeEncryptBoringSslWithBadParamTest, BadParamFails) {
  HpkeParams hpke_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<std::unique_ptr<HpkeEncryptBoringSsl>> result =
      HpkeEncryptBoringSsl::NewForTesting(
          hpke_params, params.recipient_public_key, params.application_info,
          params.seed_for_testing);
  ASSERT_THAT(result.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeEncryptBoringSslWithMissingPublicKeyTest, ZeroLengthPublicKeyFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<std::unique_ptr<HpkeEncryptBoringSsl>> result =
      HpkeEncryptBoringSsl::NewForTesting(
          hpke_params, /*recipient_public_key=*/"", params.application_info,
          params.seed_for_testing);
  ASSERT_THAT(result.status(), StatusIs(absl::StatusCode::kUnknown));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
