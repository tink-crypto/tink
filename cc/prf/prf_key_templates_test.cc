// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/prf/prf_key_templates.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::HkdfPrfKeyFormat;
using ::testing::Eq;
using ::testing::Ref;

TEST(HkdfSha256HkdfTest, Basics) {
  EXPECT_THAT(PrfKeyTemplates::HkdfSha256().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.HkdfPrfKey"));
  EXPECT_THAT(PrfKeyTemplates::HkdfSha256().type_url(),
              Eq(HkdfPrfKeyManager().get_key_type()));
}

TEST(HkdfSha256HkdfTest, OutputPrefixType) {
  EXPECT_THAT(PrfKeyTemplates::HkdfSha256().output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::TINK));
}

TEST(HkdfSha256HkdfTest, MultipleCallsSameReference) {
  EXPECT_THAT(PrfKeyTemplates::HkdfSha256(),
              Ref(PrfKeyTemplates::HkdfSha256()));
}

TEST(HkdfSha256HkdfTest, WorksWithKeyTypeManager) {
  const google::crypto::tink::KeyTemplate& key_template =
      PrfKeyTemplates::HkdfSha256();
  HkdfPrfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(HkdfPrfKeyManager().ValidateKeyFormat(key_format), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
