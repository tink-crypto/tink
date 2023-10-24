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

#include "tink/aead/internal/config_v0.h"

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
#include "tink/aead/internal/key_gen_config_v0.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/internal/ssl_util.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Not;

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

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGenV0(key_gen_config), IsOk());
  util::StatusOr<const internal::KeyTypeInfoStore*> key_gen_store =
      internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const internal::KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesCtrHmacAeadKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(AesGcmKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(AesGcmSivKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(AesEaxKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(XChaCha20Poly1305KeyManager().get_key_type()), IsOk());
  }
}

TEST(AeadV0Test, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddAeadV0(config), IsOk());

  for (const KeyTemplate& temp :
       {AeadKeyTemplates::Aes128CtrHmacSha256(), AeadKeyTemplates::Aes128Gcm(),
        AeadKeyTemplates::Aes128Eax()}) {
    util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        KeysetHandle::GenerateNew(temp, key_gen_config);
    ASSERT_THAT(handle, IsOk());

    util::StatusOr<std::unique_ptr<Aead>> aead =
        (*handle)->GetPrimitive<Aead>(config);
    ASSERT_THAT(aead, IsOk());

    std::string plaintext = "plaintext";
    util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, "ad");
    ASSERT_THAT(ciphertext, IsOk());
    EXPECT_THAT((*aead)->Decrypt(*ciphertext, "ad"), IsOkAndHolds(plaintext));
  }
}

TEST(AeadV0Test, GetPrimitiveBoringSsl) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "BoringSSL-only test.";
  }

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddAeadV0(config), IsOk());

  for (const KeyTemplate& temp : {AeadKeyTemplates::Aes128GcmSiv(),
                                  AeadKeyTemplates::XChaCha20Poly1305()}) {
    util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        KeysetHandle::GenerateNew(temp, key_gen_config);
    ASSERT_THAT(handle, IsOk());

    util::StatusOr<std::unique_ptr<Aead>> aead =
        (*handle)->GetPrimitive<Aead>(config);
    ASSERT_THAT(aead, IsOk());

    std::string plaintext = "plaintext";
    util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, "ad");
    ASSERT_THAT(ciphertext, IsOk());
    EXPECT_THAT((*aead)->Decrypt(*ciphertext, "ad"), IsOkAndHolds(plaintext));
  }
}

TEST(AeadV0Test, GetPrimitiveOpenSsl) {
  if (internal::IsBoringSsl()) {
    GTEST_SKIP() << "OpenSSL-only test.";
  }

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddAeadV0(config), IsOk());

  for (const KeyTemplate& temp : {AeadKeyTemplates::Aes128GcmSiv(),
                                  AeadKeyTemplates::XChaCha20Poly1305()}) {
    util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        KeysetHandle::GenerateNew(temp, key_gen_config);
    ASSERT_THAT(handle, IsOk());

    EXPECT_THAT((*handle)->GetPrimitive<Aead>(config), Not(IsOk()));
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
