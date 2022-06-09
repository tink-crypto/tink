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

#include "tink/hybrid/internal/hpke_context_boringssl.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/hybrid/internal/test_hpke_context_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::Values;

class HpkeContextBoringSslTest : public testing::TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeContextBoringSslTestSuite, HpkeContextBoringSslTest,
    Values(HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                      HpkeAead::kAes128Gcm},
           HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                      HpkeAead::kChaCha20Poly1305}));

TEST_P(HpkeContextBoringSslTest, Seal) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());
  util::StatusOr<SenderHpkeContextBoringSsl> hpke_context =
      TestHpkeContextBoringSsl::SetupSender(
          hpke_params, params->recipient_public_key, params->application_info,
          params->seed_for_testing);
  ASSERT_THAT(hpke_context.status(), IsOk());
  util::StatusOr<std::string> ciphertext =
      hpke_context->context->Seal(params->plaintext, params->associated_data);
  ASSERT_THAT(ciphertext, IsOkAndHolds(params->ciphertext));
}

TEST_P(HpkeContextBoringSslTest, Open) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());
  util::StatusOr<std::unique_ptr<HpkeContextBoringSsl>> hpke_context =
      HpkeContextBoringSsl::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params->recipient_private_key),
          params->encapsulated_key, params->application_info);
  ASSERT_THAT(hpke_context.status(), IsOk());
  util::StatusOr<std::string> plaintext =
      (*hpke_context)->Open(params->ciphertext, params->associated_data);
  ASSERT_THAT(plaintext, IsOkAndHolds(params->plaintext));
}

class HpkeContextBoringSslWithBadParamTest
    : public testing::TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeContextBoringSslWithBadParamTestSuite,
    HpkeContextBoringSslWithBadParamTest,
    Values(HpkeParams{HpkeKem::kUnknownKem, HpkeKdf::kHkdfSha256,
                      HpkeAead::kAes128Gcm},
           HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kUnknownKdf,
                      HpkeAead::kAes128Gcm},
           HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                      HpkeAead::kUnknownAead}));

TEST_P(HpkeContextBoringSslWithBadParamTest, BadSenderParamsFail) {
  HpkeParams hpke_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<SenderHpkeContextBoringSsl> result =
      TestHpkeContextBoringSsl::SetupSender(
          hpke_params, params.recipient_public_key, params.application_info,
          params.seed_for_testing);
  ASSERT_THAT(result.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeContextBoringSslWithBadParamTest, BadRecipientParamsFail) {
  HpkeParams hpke_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<std::unique_ptr<HpkeContextBoringSsl>> hpke_context =
      HpkeContextBoringSsl::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params.recipient_private_key),
          params.encapsulated_key, params.application_info);
  ASSERT_THAT(hpke_context.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeContextBoringSslWithMissingPublicKeyTest, ZeroLengthPublicKeyFails) {
  HpkeParams hpke_params = {HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                            HpkeAead::kAes128Gcm};
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<SenderHpkeContextBoringSsl> result =
      TestHpkeContextBoringSsl::SetupSender(
          hpke_params, /*recipient_public_key=*/"", params.application_info,
          params.seed_for_testing);
  ASSERT_THAT(result.status(), StatusIs(absl::StatusCode::kUnknown));
}

TEST(HpkeContextBoringSslWithMissingPrivateKeyTest, ZeroLengthPrivateKeyFails) {
  HpkeParams hpke_params = {HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                            HpkeAead::kAes128Gcm};
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<std::unique_ptr<HpkeContextBoringSsl>> hpke_context =
      HpkeContextBoringSsl::SetupRecipient(
          hpke_params, util::SecretDataFromStringView(/*secret=*/""),
          params.encapsulated_key, params.application_info);
  ASSERT_THAT(hpke_context.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
