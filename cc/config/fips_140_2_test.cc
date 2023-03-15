// Copyright 2023 Google LLC
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

#include "tink/config/fips_140_2.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/registry_impl.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Not;

class Fips1402Test : public ::testing::Test {
 protected:
  void TearDown() override { internal::UnSetFipsRestricted(); }
};

TEST_F(Fips1402Test, ConfigFips1402) {
  if (!FIPS_mode()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  const internal::RegistryImpl& registry =
      internal::ConfigurationImpl::get_registry(ConfigFips140_2());
  EXPECT_THAT(registry.get_key_manager<Mac>(HmacKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT(
      registry.get_key_manager<Aead>(AesCtrHmacAeadKeyManager().get_key_type()),
      IsOk());
  EXPECT_THAT(registry.get_key_manager<Aead>(AesGcmKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT(registry.get_key_manager<Prf>(HmacPrfKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT(registry.get_key_manager<PublicKeyVerify>(
                  EcdsaVerifyKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT(registry.get_key_manager<PublicKeyVerify>(
                  RsaSsaPssVerifyKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT(registry.get_key_manager<PublicKeyVerify>(
                  RsaSsaPkcs1VerifyKeyManager().get_key_type()),
              IsOk());
}

TEST_F(Fips1402Test, NonFipsKeyManagerIsNotPresent) {
  if (!FIPS_mode()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  const internal::RegistryImpl& registry =
      internal::ConfigurationImpl::get_registry(ConfigFips140_2());
  EXPECT_THAT(registry.get_key_manager<Mac>(AesCmacKeyManager().get_key_type()),
              Not(IsOk()));
}

TEST_F(Fips1402Test, ConfigFips1402FailsInNonFipsMode) {
  if (FIPS_mode()) {
    GTEST_SKIP() << "Only test in non-FIPS mode";
  }

  EXPECT_DEATH_IF_SUPPORTED(
      ConfigFips140_2(), "BoringSSL not built with the BoringCrypto module.");
}

TEST_F(Fips1402Test, NewKeyDataAndWrapKeysetSucceeds) {
  if (!FIPS_mode()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  const internal::RegistryImpl& registry =
      internal::ConfigurationImpl::get_registry(ConfigFips140_2());

  util::StatusOr<std::unique_ptr<KeyData>> key_data =
      registry.NewKeyData(AeadKeyTemplates::Aes128Gcm());
  ASSERT_THAT(key_data, IsOk());

  Keyset keyset;
  uint32_t key_id = 0;
  test::AddKeyData(**key_data, key_id, OutputPrefixType::TINK,
                   KeyStatusType::ENABLED, &keyset);
  keyset.set_primary_key_id(key_id);

  absl::flat_hash_map<std::string, std::string> annotations;
  util::StatusOr<std::unique_ptr<Aead>> aead =
      registry.WrapKeyset<Aead>(keyset, annotations);
  ASSERT_THAT(aead, IsOk());

  std::string plaintext = "plaintext";
  std::string ad = "ad";
  util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, ad);
  ASSERT_THAT(ciphertext, IsOk());

  util::StatusOr<std::string> decrypted = (*aead)->Decrypt(*ciphertext, ad);
  EXPECT_THAT(decrypted, IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
