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

#include "tink/prf/config_v0.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/keyset_handle.h"
#include "tink/prf/key_gen_config_v0.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/prf/prf_set.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

using PrfV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(PrfV0KeyTypesTestSuite, PrfV0KeyTypesTest,
                         Values(PrfKeyTemplates::AesCmac(),
                                PrfKeyTemplates::HkdfSha256(),
                                PrfKeyTemplates::HmacSha256()));

TEST_P(PrfV0KeyTypesTest, GetPrimitive) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigPrfV0());
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<PrfSet>> prf =
      (*handle)->GetPrimitive<PrfSet>(ConfigPrfV0());
  ASSERT_THAT(prf, IsOk());

  size_t output_length = 16;
  util::StatusOr<std::string> output =
      (*prf)->ComputePrimary("input", output_length);
  ASSERT_THAT(output, IsOk());
  EXPECT_THAT((*output).length(), Eq(output_length));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
