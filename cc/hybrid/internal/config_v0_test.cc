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

#include "tink/hybrid/internal/config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/configuration.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/key_gen_config_v0.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
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
using ::testing::TestWithParam;
using ::testing::Values;

TEST(HybridV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddHybridConfigV0(config), IsOk());
  util::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<HybridEncrypt>(), IsOk());
  EXPECT_THAT((*store)->Get<HybridDecrypt>(), IsOk());
}

TEST(HybridV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddHybridConfigV0(config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddHybridKeyGenConfigV0(key_gen_config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(EciesAeadHkdfPrivateKeyManager().get_key_type()),
                IsOk());
    EXPECT_THAT(s->Get(HpkePrivateKeyManager().get_key_type()), IsOk());
  }
}

using HybridV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(
    HybridV0KeyTypesTestSuite, HybridV0KeyTypesTest,
    Values(HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm(),
           HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm()));

TEST_P(HybridV0KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddHybridKeyGenConfigV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddHybridConfigV0(config), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      (*public_handle)->GetPrimitive<HybridEncrypt>(config);
  ASSERT_THAT(encrypt, IsOk());
  util::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      (*handle)->GetPrimitive<HybridDecrypt>(config);
  ASSERT_THAT(decrypt, IsOk());

  std::string plaintext = "plaintext";
  util::StatusOr<std::string> ciphertext = (*encrypt)->Encrypt(plaintext, "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "ad"), IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
