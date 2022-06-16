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

#include "tink/hybrid/internal/hpke_context.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::CreateHpkeTestParams;
using ::crypto::tink::internal::DefaultHpkeTestParams;
using ::crypto::tink::internal::HpkeTestParams;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

class HpkeContextTest : public TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeContextTestSuite, HpkeContextTest,
    Values(HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                      HpkeAead::kAes128Gcm},
           HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                      HpkeAead::kChaCha20Poly1305}));

TEST_P(HpkeContextTest, SealAndOpen) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());

  util::StatusOr<std::unique_ptr<HpkeContext>> sender_hpke_context =
      HpkeContext::SetupSender(hpke_params, params->recipient_public_key,
                               params->application_info);
  ASSERT_THAT(sender_hpke_context.status(), IsOk());

  util::StatusOr<std::unique_ptr<HpkeContext>> recipient_hpke_context =
      HpkeContext::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params->recipient_private_key),
          (*sender_hpke_context)->EncapsulatedKey(), params->application_info);
  ASSERT_THAT(recipient_hpke_context.status(), IsOk());

  std::vector<std::string> inputs = {"", params->plaintext};
  std::vector<std::string> context_infos = {"", params->application_info};
  for (const std::string& input : inputs) {
    for (const std::string& context_info : context_infos) {
      SCOPED_TRACE(absl::StrCat("plaintext: '", input, "', context_info: '",
                                context_info, "'"));
      util::StatusOr<std::string> ciphertext =
          (*sender_hpke_context)->Seal(input, context_info);
      ASSERT_THAT(ciphertext.status(), IsOk());

      util::StatusOr<std::string> plaintext =
          (*recipient_hpke_context)->Open(*ciphertext, context_info);
      ASSERT_THAT(plaintext.status(), IsOk());

      EXPECT_THAT(*plaintext, Eq(input));
    }
  }
}

TEST_P(HpkeContextTest, Export) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());

  util::StatusOr<std::unique_ptr<HpkeContext>> sender_hpke_context =
      HpkeContext::SetupSender(hpke_params, params->recipient_public_key,
                               params->application_info);
  ASSERT_THAT(sender_hpke_context.status(), IsOk());

  util::StatusOr<std::unique_ptr<HpkeContext>> recipient_hpke_context =
      HpkeContext::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params->recipient_private_key),
          (*sender_hpke_context)->EncapsulatedKey(), params->application_info);
  ASSERT_THAT(recipient_hpke_context.status(), IsOk());

  std::vector<std::string> exporter_contexts = {"", "c", "context"};
  std::vector<int> secret_lengths = {0, 8, 16, 32, 64};
  for (const std::string& exporter_context : exporter_contexts) {
    for (int secret_length : secret_lengths) {
      SCOPED_TRACE(absl::StrCat("exporter_context: '", exporter_context,
                                "', secret_length: '", secret_length, "'"));
      util::StatusOr<util::SecretData> sender_secret =
          (*sender_hpke_context)->Export(exporter_context, secret_length);
      ASSERT_THAT(sender_secret.status(), IsOk());

      util::StatusOr<util::SecretData> recipient_secret =
          (*recipient_hpke_context)->Export(exporter_context, secret_length);
      ASSERT_THAT(recipient_secret.status(), IsOk());

      EXPECT_THAT(*sender_secret, Eq(*recipient_secret));
    }
  }
}

TEST_P(HpkeContextTest, OpenTruncatedCiphertextFails) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());

  util::StatusOr<std::unique_ptr<HpkeContext>> recipient_hpke_context =
      HpkeContext::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params->recipient_private_key),
          params->encapsulated_key, params->application_info);
  ASSERT_THAT(recipient_hpke_context.status(), IsOk());

  util::StatusOr<std::string> plaintext =
      (*recipient_hpke_context)
          ->Open(params->ciphertext, params->associated_data);
  ASSERT_THAT(plaintext.status(), IsOk());

  const std::string truncated_ciphertext =
      params->ciphertext.substr(params->ciphertext.length() - 1);
  util::StatusOr<std::string> bad_plaintext =
      (*recipient_hpke_context)
          ->Open(truncated_ciphertext, params->associated_data);
  EXPECT_THAT(bad_plaintext.status(), StatusIs(absl::StatusCode::kUnknown));
}

TEST_P(HpkeContextTest, OpenModifiedCiphertextFails) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());

  util::StatusOr<std::unique_ptr<HpkeContext>> recipient_hpke_context =
      HpkeContext::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params->recipient_private_key),
          params->encapsulated_key, params->application_info);
  ASSERT_THAT(recipient_hpke_context.status(), IsOk());

  util::StatusOr<std::string> plaintext =
      (*recipient_hpke_context)
          ->Open(params->ciphertext, params->associated_data);
  ASSERT_THAT(plaintext.status(), IsOk());

  const std::string modified_ciphertext =
      absl::StrCat(params->ciphertext, "modification");
  util::StatusOr<std::string> bad_plaintext =
      (*recipient_hpke_context)
          ->Open(modified_ciphertext, params->associated_data);
  EXPECT_THAT(bad_plaintext.status(), StatusIs(absl::StatusCode::kUnknown));
}

TEST_P(HpkeContextTest, OpenModifiedAssociatedDataFails) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());

  util::StatusOr<std::unique_ptr<HpkeContext>> recipient_hpke_context =
      HpkeContext::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params->recipient_private_key),
          params->encapsulated_key, params->application_info);
  ASSERT_THAT(recipient_hpke_context.status(), IsOk());

  util::StatusOr<std::string> plaintext =
      (*recipient_hpke_context)
          ->Open(params->ciphertext, params->associated_data);
  ASSERT_THAT(plaintext.status(), IsOk());

  const std::string modified_associated_data =
      absl::StrCat(params->associated_data, "modification");
  util::StatusOr<std::string> bad_plaintext =
      (*recipient_hpke_context)
          ->Open(params->ciphertext, modified_associated_data);
  EXPECT_THAT(bad_plaintext.status(), StatusIs(absl::StatusCode::kUnknown));
}

class HpkeContextWithBadHpkeParamTest : public TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeContextWithBadHpkeParamTestTestSuite, HpkeContextWithBadHpkeParamTest,
    Values(HpkeParams{HpkeKem::kUnknownKem, HpkeKdf::kHkdfSha256,
                      HpkeAead::kAes128Gcm},
           HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kUnknownKdf,
                      HpkeAead::kAes256Gcm},
           HpkeParams{HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                      HpkeAead::kUnknownAead}));

TEST_P(HpkeContextWithBadHpkeParamTest, SenderBadHpkeParamFails) {
  HpkeParams hpke_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();

  util::StatusOr<std::unique_ptr<HpkeContext>> sender_hpke_context =
      HpkeContext::SetupSender(hpke_params, params.recipient_public_key,
                               params.application_info);
  EXPECT_THAT(sender_hpke_context.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeContextWithBadHpkeParamTest, RecipientBadHpkeParamFails) {
  HpkeParams hpke_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();

  util::StatusOr<std::unique_ptr<HpkeContext>> recipient_hpke_context =
      HpkeContext::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params.recipient_private_key),
          params.encapsulated_key, params.application_info);
  EXPECT_THAT(recipient_hpke_context.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeContextZeroLengthKeyTest, ZeroLengthPublicKeyFails) {
  HpkeParams hpke_params = {HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                            HpkeAead::kAes256Gcm};
  HpkeTestParams params = DefaultHpkeTestParams();

  util::StatusOr<std::unique_ptr<HpkeContext>> sender_hpke_context =
      HpkeContext::SetupSender(hpke_params, /*recipient_public_key=*/"",
                               params.application_info);
  EXPECT_THAT(sender_hpke_context.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeContextZeroLengthKeyTest, ZeroLengthPrivateKeyFails) {
  HpkeParams hpke_params = {HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                            HpkeAead::kAes256Gcm};
  HpkeTestParams params = DefaultHpkeTestParams();

  util::StatusOr<std::unique_ptr<HpkeContext>> recipient_hpke_context =
      HpkeContext::SetupRecipient(
          hpke_params,
          /*recipient_private_key=*/util::SecretDataFromStringView(""),
          params.encapsulated_key, params.application_info);
  EXPECT_THAT(recipient_hpke_context.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeContextZeroLengthKeyTest, ZeroLengthEncapsulatedKeyFails) {
  HpkeParams hpke_params = {HpkeKem::kX25519HkdfSha256, HpkeKdf::kHkdfSha256,
                            HpkeAead::kAes256Gcm};
  HpkeTestParams params = DefaultHpkeTestParams();

  util::StatusOr<std::unique_ptr<HpkeContext>> recipient_hpke_context =
      HpkeContext::SetupRecipient(
          hpke_params,
          util::SecretDataFromStringView(params.recipient_private_key),
          /*encapsulated_key=*/"", params.application_info);
  EXPECT_THAT(recipient_hpke_context.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ConcatenatePayloadTest, ConcatenatePayloadSucceeds) {
  HpkeTestParams params = DefaultHpkeTestParams();
  EXPECT_THAT(ConcatenatePayload(params.encapsulated_key, params.ciphertext),
              Eq(absl::StrCat(params.encapsulated_key, params.ciphertext)));
}

TEST(SplitPayloadTest, SplitPayloadSucceeds) {
  HpkeTestParams params = DefaultHpkeTestParams();
  const std::string payload =
      absl::StrCat(params.encapsulated_key, params.ciphertext);
  util::StatusOr<HpkePayloadView> hpke_payload =
      SplitPayload(HpkeKem::kX25519HkdfSha256, payload);
  ASSERT_THAT(hpke_payload.status(), IsOk());
  EXPECT_THAT(hpke_payload->encapsulated_key, Eq(params.encapsulated_key));
  EXPECT_THAT(hpke_payload->ciphertext, Eq(params.ciphertext));
}

TEST(SplitPayloadTest, InvalidKemFails) {
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<HpkePayloadView> payload =
      SplitPayload(HpkeKem::kUnknownKem,
                   absl::StrCat(params.encapsulated_key, params.ciphertext));
  EXPECT_THAT(payload.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
