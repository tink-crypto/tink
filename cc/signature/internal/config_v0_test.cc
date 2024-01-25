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

#include "tink/signature/internal/config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/internal/key_gen_config_v0.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(SignatureV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());
  util::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<PublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeyVerify>(), IsOk());
}

TEST(SignatureV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(EcdsaVerifyKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(Ed25519VerifyKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(RsaSsaPkcs1VerifyKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(RsaSsaPssVerifyKeyManager().get_key_type()), IsOk());
  }
}

using SignatureV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(
    SignatureV0KeyTypesTestSuite, SignatureV0KeyTypesTest,
    Values(SignatureKeyTemplates::EcdsaP256(), SignatureKeyTemplates::Ed25519(),
           SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4(),
           SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4()));

TEST_P(SignatureV0KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
