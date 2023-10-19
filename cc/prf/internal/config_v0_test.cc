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

#include "tink/prf/internal/config_v0.h"

#include <cstddef>
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
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/internal/key_gen_config_v0.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/prf/prf_set.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(PrfV0Test, PrimitiveWrapper) {
  Configuration config;
  ASSERT_THAT(AddPrfV0(config), IsOk());
  util::StatusOr<const internal::KeysetWrapperStore*> store =
      internal::ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<PrfSet>(), IsOk());
}

TEST(PrfV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddPrfV0(config), IsOk());
  util::StatusOr<const internal::KeyTypeInfoStore*> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPrfKeyGenV0(key_gen_config), IsOk());
  util::StatusOr<const internal::KeyTypeInfoStore*> key_gen_store =
      internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const internal::KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesCmacPrfKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(HkdfPrfKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(HmacPrfKeyManager().get_key_type()), IsOk());
  }
}

using PrfV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(PrfV0KeyTypesTestSuite, PrfV0KeyTypesTest,
                         Values(PrfKeyTemplates::AesCmac(),
                                PrfKeyTemplates::HkdfSha256(),
                                PrfKeyTemplates::HmacSha256()));

TEST_P(PrfV0KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPrfKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPrfV0(config), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<PrfSet>> prf =
      (*handle)->GetPrimitive<PrfSet>(config);
  ASSERT_THAT(prf, IsOk());

  size_t output_length = 16;
  util::StatusOr<std::string> output =
      (*prf)->ComputePrimary("input", output_length);
  ASSERT_THAT(output, IsOk());
  EXPECT_THAT((*output).length(), Eq(output_length));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
