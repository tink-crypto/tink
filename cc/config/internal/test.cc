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

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/config/internal/aead_v0.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;

TEST(AeadV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddAeadV0(config), IsOk());
  util::StatusOr<const internal::KeysetWrapperStore*> store =
      internal::ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<Aead>(), IsOk());
}

TEST(AeadV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddAeadV0(config), IsOk());
  util::StatusOr<const internal::KeyTypeInfoStore*> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get(AesCtrHmacAeadKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesGcmKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesGcmSivKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesEaxKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(XChaCha20Poly1305KeyManager().get_key_type()),
              IsOk());
}

TEST(AeadV0Test, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), key_gen_config),
              IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  Configuration config;
  ASSERT_THAT(AddAeadV0(config), IsOk());
  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(config);
  ASSERT_THAT(aead, IsOk());

  std::string plaintext = "plaintext";
  std::string ad = "ad";
  util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, ad);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, ad), IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
