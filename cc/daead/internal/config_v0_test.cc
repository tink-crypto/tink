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

#include "tink/daead/internal/config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/configuration.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/daead/internal/key_gen_config_v0.h"
#include "tink/deterministic_aead.h"
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

TEST(DeterministicAeadV0Test, PrimitiveWrapper) {
  Configuration config;
  ASSERT_THAT(AddDeterministicAeadV0(config), IsOk());
  util::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<DeterministicAead>(), IsOk());
}

TEST(DeterministicAeadV0Test, KeyManager) {
  Configuration config;
  ASSERT_THAT(AddDeterministicAeadV0(config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddDeterministicAeadKeyGenV0(key_gen_config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesSivKeyManager().get_key_type()), IsOk());
  }
}

TEST(DeterministicAeadV0Test, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddDeterministicAeadKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddDeterministicAeadV0(config), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(DeterministicAeadKeyTemplates::Aes256Siv(),
                                key_gen_config);
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      (*handle)->GetPrimitive<DeterministicAead>(config);
  ASSERT_THAT(daead, IsOk());

  std::string plaintext = "plaintext";
  util::StatusOr<std::string> ciphertext =
      (*daead)->EncryptDeterministically(plaintext, "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*daead)->DecryptDeterministically(*ciphertext, "ad"),
              IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
