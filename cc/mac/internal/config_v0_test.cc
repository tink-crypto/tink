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

#include "tink/mac/internal/config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/chunked_mac.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/internal/key_gen_config_v0.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(MacV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddMacV0(config), IsOk());
  util::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<Mac>(), IsOk());
  EXPECT_THAT((*store)->Get<ChunkedMac>(), IsOk());
}

TEST(MacV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddMacV0(config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGenV0(key_gen_config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesCmacKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(HmacKeyManager().get_key_type()), IsOk());
  }
}

using MacV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(MacV0KeyTypesTestSuite, MacV0KeyTypesTest,
                         Values(MacKeyTemplates::AesCmac(),
                                MacKeyTemplates::HmacSha256()));

TEST_P(MacV0KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddMacV0(config), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<Mac>> mac =
      (*handle)->GetPrimitive<Mac>(config);
  ASSERT_THAT(mac, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> tag = (*mac)->ComputeMac(data);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, data), IsOk());
}

TEST_P(MacV0KeyTypesTest, GetPrimitiveChunkedMac) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddMacV0(config), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      (*handle)->GetPrimitive<ChunkedMac>(config);
  ASSERT_THAT(chunked_mac, IsOk());

  std::string data1 = "da";
  std::string data2 = "ta";

  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> compute =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(compute, IsOk());
  ASSERT_THAT((*compute)->Update(data1), IsOk());
  ASSERT_THAT((*compute)->Update(data2), IsOk());
  util::StatusOr<std::string> tag = (*compute)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verify =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verify, IsOk());
  ASSERT_THAT((*verify)->Update(data1), IsOk());
  ASSERT_THAT((*verify)->Update(data2), IsOk());
  EXPECT_THAT((*verify)->VerifyMac(), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
