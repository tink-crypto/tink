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

#include "tink/hybrid/internal/hpke_encrypt.h"

#include <string>

#include "gtest/gtest.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::CreateHpkeParams;
using ::crypto::tink::internal::CreateHpkePublicKey;
using ::crypto::tink::internal::CreateHpkeTestParams;
using ::crypto::tink::internal::DefaultHpkeTestParams;
using ::crypto::tink::internal::HpkeTestParams;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::HpkePublicKey;
using ::testing::Values;

class HpkeEncryptTest : public testing::TestWithParam<HpkeParams> {};

INSTANTIATE_TEST_SUITE_P(
    HpkeEncryptionTestSuite, HpkeEncryptTest,
    Values(CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY1305),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AES_256_GCM)));

TEST_P(HpkeEncryptTest, SetupSenderContextAndEncrypt) {
  HpkeParams hpke_params = GetParam();
  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params.status(), IsOk());
  HpkePublicKey recipient_key =
      CreateHpkePublicKey(hpke_params, params->recipient_public_key);
  util::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);
  ASSERT_THAT(hpke_encrypt.status(), IsOk());

  std::vector<std::string> plaintexts = {"", params->plaintext};
  std::vector<std::string> context_infos = {"", params->application_info};
  for (const std::string& plaintext : plaintexts) {
    for (const std::string& context_info : context_infos) {
      SCOPED_TRACE(absl::StrCat("plaintext: '", plaintext, "', context_info: '",
                                context_info, "'"));
      util::StatusOr<std::string> encryption =
          (*hpke_encrypt)->Encrypt(plaintext, context_info);
      ASSERT_THAT(encryption.status(), IsOk());
    }
  }
}

class HpkeEncryptWithBadParamTest : public testing::TestWithParam<HpkeParams> {
};

INSTANTIATE_TEST_SUITE_P(
    HpkeEncryptionWithBadParamTestSuite, HpkeEncryptWithBadParamTest,
    Values(CreateHpkeParams(HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256,
                            HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::KDF_UNKNOWN, HpkeAead::AES_128_GCM),
           CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            HpkeKdf::HKDF_SHA256, HpkeAead::AEAD_UNKNOWN)));

TEST_P(HpkeEncryptWithBadParamTest, BadParamFails) {
  HpkeParams hpke_params = GetParam();
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePublicKey recipient_key =
      CreateHpkePublicKey(hpke_params, params.recipient_public_key);
  util::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);
  ASSERT_THAT(hpke_encrypt.status(), IsOk());

  util::StatusOr<std::string> encryption =
      (*hpke_encrypt)->Encrypt(params.plaintext, params.application_info);

  ASSERT_THAT(encryption.status(), StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(HpkeEncryptWithZeroLengthPublicKey, ZeroLengthPublicKeyFails) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  HpkePublicKey recipient_key =
      CreateHpkePublicKey(hpke_params, /*raw_key_bytes=*/"");

  util::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);

  ASSERT_THAT(hpke_encrypt.status(), StatusIs(util::error::INVALID_ARGUMENT));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
