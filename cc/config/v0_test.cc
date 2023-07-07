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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/configuration.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#include "tink/internal/configuration_impl.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;

TEST(V0Test, ConfigV0) {
  util::StatusOr<const internal::KeyTypeInfoStore*> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(ConfigV0());
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get(HmacKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesCmacKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesCtrHmacAeadKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesGcmKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesGcmSivKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesEaxKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(XChaCha20Poly1305KeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(AesSivKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesGcmHkdfStreamingKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(AesCtrHmacStreamingKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(EciesAeadHkdfPublicKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(internal::HpkePublicKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(HmacPrfKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(HkdfPrfKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesCmacPrfKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(EcdsaVerifyKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(RsaSsaPssVerifyKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(RsaSsaPkcs1VerifyKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(Ed25519VerifyKeyManager().get_key_type()), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
