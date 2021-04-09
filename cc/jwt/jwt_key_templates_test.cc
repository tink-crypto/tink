// Copyright 2021 Google LLC
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

#include "tink/jwt/jwt_key_templates.h"

#include "gtest/gtest.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_mac_config.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using google::crypto::tink::KeyTemplate;

namespace crypto {
namespace tink {
namespace {

class JwtKeyTemplatesTest : public testing::TestWithParam<KeyTemplate> {
  void SetUp() override { ASSERT_TRUE(JwtMacRegister().ok()); }
};

TEST_P(JwtKeyTemplatesTest, CreateComputeVerify) {
  KeyTemplate key_template = GetParam();

  auto handle_result = KeysetHandle::GenerateNew(key_template);
  ASSERT_THAT(handle_result.status(), IsOk());
  auto keyset_handle = std::move(handle_result.ValueOrDie());
  auto jwt_mac_or = keyset_handle->GetPrimitive<JwtMac>();
  ASSERT_THAT(jwt_mac_or.status(), IsOk());
  std::unique_ptr<JwtMac> jwt_mac = std::move(jwt_mac_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  RawJwt raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or =
      jwt_mac->ComputeMacAndEncode(raw_jwt);
  ASSERT_THAT(compact_or.status(), IsOk());
  std::string compact = compact_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();
  util::StatusOr<VerifiedJwt> verified_jwt_or =
      jwt_mac->VerifyMacAndDecode(compact, validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  auto verified_jwt = verified_jwt_or.ValueOrDie();
  EXPECT_THAT(verified_jwt.GetIssuer(), test::IsOkAndHolds("issuer"));

  JwtValidator validator2 = JwtValidatorBuilder().SetIssuer("unknown").Build();
  EXPECT_FALSE(jwt_mac->VerifyMacAndDecode(compact, validator2).ok());
}

INSTANTIATE_TEST_SUITE_P(JwtKeyTemplatesTest, JwtKeyTemplatesTest,
                         testing::Values(JwtHs256Template(), JwtHs384Template(),
                                         JwtHs512Template()));

}  // namespace
}  // namespace tink
}  // namespace crypto
