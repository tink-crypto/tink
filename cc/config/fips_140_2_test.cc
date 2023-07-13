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
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/chunked_mac.h"
#include "tink/config/key_gen_fips_140_2.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;

class Fips1402Test : public ::testing::Test {
 protected:
  void TearDown() override { internal::UnSetFipsRestricted(); }
};

TEST_F(Fips1402Test, PrimitiveWrappers) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  util::StatusOr<const internal::KeysetWrapperStore*> store =
      internal::ConfigurationImpl::GetKeysetWrapperStore(ConfigFips140_2());
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<Mac>(), IsOk());
  EXPECT_THAT((*store)->Get<ChunkedMac>(), IsOk());
  EXPECT_THAT((*store)->Get<Aead>(), IsOk());
  EXPECT_THAT((*store)->Get<PrfSet>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeyVerify>(), IsOk());
}

TEST_F(Fips1402Test, KeyManagers) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  util::StatusOr<const internal::KeyTypeInfoStore*> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(ConfigFips140_2());
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get(HmacKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesCtrHmacAeadKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesGcmKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(HmacPrfKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(EcdsaVerifyKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(RsaSsaPssVerifyKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(RsaSsaPkcs1VerifyKeyManager().get_key_type()),
              IsOk());
}

TEST_F(Fips1402Test, FailsInNonFipsMode) {
  if (internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in non-FIPS mode";
  }

  EXPECT_DEATH_IF_SUPPORTED(
      ConfigFips140_2(), "BoringSSL not built with the BoringCrypto module.");
}

TEST_F(Fips1402Test, NonFipsTypeNotPresent) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  util::StatusOr<const internal::KeyTypeInfoStore*> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(ConfigFips140_2());
  ASSERT_THAT(store, IsOk());
  EXPECT_THAT((*store)->Get(AesCmacKeyManager().get_key_type()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(Fips1402Test, GetPrimitive) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigFips140_2());
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(ConfigFips140_2());
  ASSERT_THAT(aead, IsOk());

  std::string plaintext = "plaintext";
  std::string ad = "ad";
  util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, ad);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, ad), IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
