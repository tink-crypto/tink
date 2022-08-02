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

#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/test_matchers.h"
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
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::HpkePublicKey;
using ::testing::SizeIs;
using ::testing::Values;

constexpr int kTagLength = 16;  // Tag length (in bytes) for GCM and Poly1305.

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
  util::StatusOr<uint32_t> encapsulated_key_length =
      internal::HpkeEncapsulatedKeyLength(hpke_params.kem());
  ASSERT_THAT(encapsulated_key_length, IsOk());

  util::StatusOr<HpkeTestParams> params = CreateHpkeTestParams(hpke_params);
  ASSERT_THAT(params, IsOk());
  HpkePublicKey recipient_key =
      CreateHpkePublicKey(hpke_params, params->recipient_public_key);
  util::StatusOr<std::unique_ptr<HybridEncrypt>> hpke_encrypt =
      HpkeEncrypt::New(recipient_key);
  ASSERT_THAT(hpke_encrypt, IsOk());

  std::vector<std::string> plaintexts = {"", params->plaintext};
  std::vector<std::string> context_infos = {"", params->application_info};
  for (const std::string& plaintext : plaintexts) {
    for (const std::string& context_info : context_infos) {
      SCOPED_TRACE(absl::StrCat("plaintext: '", plaintext, "', context_info: '",
                                context_info, "'"));
      int expected_ciphertext_length =
          *encapsulated_key_length + plaintext.size() + kTagLength;
      util::StatusOr<std::string> encryption_result =
          (*hpke_encrypt)->Encrypt(plaintext, context_info);
      EXPECT_THAT(encryption_result,
                  IsOkAndHolds(SizeIs(expected_ciphertext_length)));
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
  ASSERT_THAT(hpke_encrypt, IsOk());

  util::StatusOr<std::string> encryption_result =
      (*hpke_encrypt)->Encrypt(params.plaintext, params.application_info);

  EXPECT_THAT(encryption_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
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

  EXPECT_THAT(hpke_encrypt.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
