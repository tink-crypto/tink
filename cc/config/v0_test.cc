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
////////////////////////////////////////////////////////////////////////////////

#include "tink/config/v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/chunked_mac.h"
#include "tink/config/key_gen_v0.h"
#include "tink/configuration.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/deterministic_aead.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/prf_set.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(V0Test, PrimitiveWrappers) {
  util::StatusOr<const internal::KeysetWrapperStore*> store =
      internal::ConfigurationImpl::GetKeysetWrapperStore(ConfigV0());
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<Mac>(), IsOk());
  EXPECT_THAT((*store)->Get<ChunkedMac>(), IsOk());
  EXPECT_THAT((*store)->Get<Aead>(), IsOk());
  EXPECT_THAT((*store)->Get<DeterministicAead>(), IsOk());
  EXPECT_THAT((*store)->Get<StreamingAead>(), IsOk());
  EXPECT_THAT((*store)->Get<HybridEncrypt>(), IsOk());
  EXPECT_THAT((*store)->Get<HybridDecrypt>(), IsOk());
  EXPECT_THAT((*store)->Get<PrfSet>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeyVerify>(), IsOk());
}

using V0KeyTypesTest =
    TestWithParam<util::StatusOr<const internal::KeyTypeInfoStore*>>;

INSTANTIATE_TEST_SUITE_P(
    V0KeyTypesTestSuite, V0KeyTypesTest,
    Values(internal::ConfigurationImpl::GetKeyTypeInfoStore(ConfigV0()),
           internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(
               KeyGenConfigV0())));

TEST_P(V0KeyTypesTest, KeyManagers) {
  ASSERT_THAT(GetParam(), IsOk());
  const crypto::tink::internal::KeyTypeInfoStore* store = GetParam().value();

  EXPECT_THAT(store->Get(HmacKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(AesCmacKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(AesCtrHmacAeadKeyManager().get_key_type()), IsOk());

  EXPECT_THAT(store->Get(AesGcmKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(AesGcmSivKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(AesEaxKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(XChaCha20Poly1305KeyManager().get_key_type()), IsOk());

  EXPECT_THAT(store->Get(AesSivKeyManager().get_key_type()), IsOk());

  EXPECT_THAT(store->Get(AesGcmHkdfStreamingKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT(store->Get(AesCtrHmacStreamingKeyManager().get_key_type()),
              IsOk());

  EXPECT_THAT(store->Get(EciesAeadHkdfPublicKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT(store->Get(internal::HpkePublicKeyManager().get_key_type()),
              IsOk());

  EXPECT_THAT(store->Get(HmacPrfKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(HkdfPrfKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(AesCmacPrfKeyManager().get_key_type()), IsOk());

  EXPECT_THAT(store->Get(EcdsaVerifyKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(RsaSsaPssVerifyKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(RsaSsaPkcs1VerifyKeyManager().get_key_type()), IsOk());
  EXPECT_THAT(store->Get(Ed25519VerifyKeyManager().get_key_type()), IsOk());
}

TEST(V0Test, GetPrimitive) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigV0());
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(ConfigV0());
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
