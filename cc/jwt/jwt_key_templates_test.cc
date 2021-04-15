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
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_mac_config.h"
#include "tink/jwt/jwt_signature_config.h"
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

class JwtMacKeyTemplatesTest : public testing::TestWithParam<KeyTemplate> {
  void SetUp() override { ASSERT_TRUE(JwtMacRegister().ok()); }
};

TEST_P(JwtMacKeyTemplatesTest, CreateComputeVerify) {
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

INSTANTIATE_TEST_SUITE_P(JwtMacKeyTemplatesTest, JwtMacKeyTemplatesTest,
                         testing::Values(JwtHs256Template(), JwtHs384Template(),
                                         JwtHs512Template()));

class JwtSignatureKeyTemplatesTest
    : public testing::TestWithParam<KeyTemplate> {
  void SetUp() override { ASSERT_TRUE(JwtSignatureRegister().ok()); }
};

TEST_P(JwtSignatureKeyTemplatesTest, CreateComputeVerify) {
  KeyTemplate key_template = GetParam();

  auto handle_result = KeysetHandle::GenerateNew(key_template);
  ASSERT_THAT(handle_result.status(), IsOk());
  auto keyset_handle = std::move(handle_result.ValueOrDie());
  auto sign_or = keyset_handle->GetPrimitive<JwtPublicKeySign>();
  ASSERT_THAT(sign_or.status(), IsOk());
  std::unique_ptr<JwtPublicKeySign> sign = std::move(sign_or.ValueOrDie());
  auto public_handle_or = keyset_handle->GetPublicKeysetHandle();
  ASSERT_THAT(public_handle_or.status(), IsOk());
  auto verify_or =
      public_handle_or.ValueOrDie()->GetPrimitive<JwtPublicKeyVerify>();
  ASSERT_THAT(verify_or.status(), IsOk());
  std::unique_ptr<JwtPublicKeyVerify> verify =
      std::move(verify_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  RawJwt raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or = sign->SignAndEncode(raw_jwt);
  ASSERT_THAT(compact_or.status(), IsOk());
  std::string compact = compact_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();
  util::StatusOr<VerifiedJwt> verified_jwt_or =
      verify->VerifyAndDecode(compact, validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  auto verified_jwt = verified_jwt_or.ValueOrDie();
  EXPECT_THAT(verified_jwt.GetIssuer(), test::IsOkAndHolds("issuer"));

  JwtValidator validator2 = JwtValidatorBuilder().SetIssuer("unknown").Build();
  EXPECT_FALSE(verify->VerifyAndDecode(compact, validator2).ok());
}

INSTANTIATE_TEST_SUITE_P(
    JwtSignatureKeyTemplatesTest, JwtSignatureKeyTemplatesTest,
    testing::Values(JwtEs256Template(), JwtEs384Template(), JwtEs512Template(),
                    JwtRs256_2048_F4_Template(), JwtRs256_3072_F4_Template(),
                    JwtRs384_3072_F4_Template(), JwtRs512_4096_F4_Template(),
                    JwtPs256_2048_F4_Template(), JwtPs256_3072_F4_Template(),
                    JwtPs384_3072_F4_Template(), JwtPs512_4096_F4_Template()));
}  // namespace
}  // namespace tink
}  // namespace crypto
