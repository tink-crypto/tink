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

#include "tink/hybrid/internal/hpke_decrypt.h"

#include <string>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/hybrid/internal/hpke_encrypt.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::CreateHpkeParams;
using ::crypto::tink::internal::CreateHpkePrivateKey;
using ::crypto::tink::internal::CreateHpkePublicKey;
using ::crypto::tink::internal::CreateHpkeTestParams;
using ::crypto::tink::internal::DefaultHpkeTestParams;
using ::crypto::tink::internal::HpkeTestParams;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::HpkePrivateKey;
using ::google::crypto::tink::HpkePublicKey;
using ::testing::Values;

util::StatusOr<std::string> Encrypt(HpkeParams params,
                                    absl::string_view recipient_public_key,
                                    absl::string_view plaintext,
                                    absl::string_view context_info) {
  HpkePublicKey recipient_key =
      CreateHpkePublicKey(params, std::string(recipient_public_key));
  util::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);
  if (!hpke_encrypt.ok()) {
    return hpke_encrypt.status();
  }
  return (*hpke_encrypt)->Encrypt(plaintext, context_info);
}

class HpkeDecryptTest : public testing::TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeDecryptionTestSuite, HpkeDecryptTest,
    Values(CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256,
                            HpkeAead::CHACHA20_POLY1305)));

TEST_P(HpkeDecryptTest, SetupRecipientContextAndDecrypt) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());
  HpkePrivateKey recipient_key =
      CreateHpkePrivateKey(hpke_params, params->recipient_private_key);
  util::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt.status(), IsOk());

  std::vector<std::string> inputs = {"", params->plaintext};
  std::vector<std::string> context_infos = {"", params->application_info};
  for (const std::string& input : inputs) {
    for (const std::string& context_info : context_infos) {
      SCOPED_TRACE(absl::StrCat("input: '", input, "', context_info: '",
                                context_info, "'"));
      util::StatusOr<std::string> ciphertext = Encrypt(
          hpke_params, params->recipient_public_key, input, context_info);
      ASSERT_THAT(ciphertext.status(), IsOk());
      util::StatusOr<std::string> plaintext =
          (*hpke_decrypt)->Decrypt(*ciphertext, context_info);
      ASSERT_THAT(plaintext, IsOkAndHolds(input));
    }
  }
}

class HpkeDecryptWithBadParamTest : public testing::TestWithParam<HpkeParams> {
};

INSTANTIATE_TEST_SUITE_P(
    HpkeDecryptionWithBadParamTestSuite, HpkeDecryptWithBadParamTest,
    Values(CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::KDF_UNKNOWN, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AEAD_UNKNOWN)));

TEST_P(HpkeDecryptWithBadParamTest, BadParamsFails) {
  HpkeParams bad_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKey recipient_key =
      CreateHpkePrivateKey(bad_params, params.recipient_private_key);
  util::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt.status(), IsOk());

  util::StatusOr<std::string> decryption =
      (*hpke_decrypt)->Decrypt(params.ciphertext, params.application_info);

  ASSERT_THAT(decryption.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeDecryptWithBadKemTest, BadKemFails) {
  HpkeParams hpke_params = CreateHpkeParams(
      HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKey recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);

  util::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);

  ASSERT_THAT(hpke_decrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeDecryptWithBadCiphertextTest, BadCiphertextFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKey recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  util::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt.status(), IsOk());
  util::StatusOr<std::string> ciphertext =
      Encrypt(hpke_params, params.recipient_public_key, params.plaintext,
              params.application_info);
  ASSERT_THAT(ciphertext.status(), IsOk());

  util::StatusOr<std::string> plaintext =
      (*hpke_decrypt)
          ->Decrypt(absl::StrCat(*ciphertext, "modified ciphertext"),
                    params.application_info);

  ASSERT_THAT(plaintext.status(), StatusIs(util::error::UNKNOWN));
}

TEST(HpkeDecryptWithBadAssociatedDataTest, BadAssociatedDataFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKey recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  util::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);
  ASSERT_THAT(hpke_decrypt.status(), IsOk());
  util::StatusOr<std::string> ciphertext =
      Encrypt(hpke_params, params.recipient_public_key, params.plaintext,
              params.application_info);
  ASSERT_THAT(ciphertext.status(), IsOk());

  util::StatusOr<std::string> plaintext =
      (*hpke_decrypt)
          ->Decrypt(*ciphertext,
                    absl::StrCat(params.application_info, "modified aad"));

  ASSERT_THAT(plaintext.status(), StatusIs(util::error::UNKNOWN));
}

TEST(HpkeDecryptWithMissingPublicKeyTest, MissingPublicKeyFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKey recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  recipient_key.clear_public_key();

  util::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);

  ASSERT_THAT(hpke_decrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeDecryptWithMissingHpkeParamsTest, MissingHpkeParamsFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKey recipient_key =
      CreateHpkePrivateKey(hpke_params, params.recipient_private_key);
  recipient_key.mutable_public_key()->clear_params();

  util::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);

  ASSERT_THAT(hpke_decrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeDecryptWithZeroLengthPrivateKeyTest, ZeroLengthPrivateKeyFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePrivateKey recipient_key =
      CreateHpkePrivateKey(hpke_params, /*raw_key_bytes=*/"");

  util::StatusOr<std::unique_ptr<HybridDecrypt>> hpke_decrypt =
      HpkeDecrypt::New(recipient_key);

  ASSERT_THAT(hpke_decrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
