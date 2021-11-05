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
///////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/internal/jwt_mac_impl.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Eq;
using ::testing::Not;

namespace crypto {
namespace tink {
namespace jwt_internal {

namespace {

util::StatusOr<std::unique_ptr<JwtMacInternal>> CreateJwtMac() {
  std::string key_value;
  if (!absl::WebSafeBase64Unescape(
          "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1"
          "qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          &key_value)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to parse key");
  }
  crypto::tink::util::StatusOr<std::unique_ptr<Mac>> mac =
      subtle::HmacBoringSsl::New(
          util::Enums::ProtoToSubtle(google::crypto::tink::HashType::SHA256),
          32, util::SecretDataFromStringView(key_value));
  if (!mac.ok()) {
    return mac.status();
  }
  std::unique_ptr<JwtMacInternal> jwt_mac = absl::make_unique<JwtMacImpl>(
      *std::move(mac), "HS256", /*kid=*/absl::nullopt);
  return jwt_mac;
}

TEST(JwtMacImplTest, CreateAndValidateToken) {
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac = CreateJwtMac();
  ASSERT_THAT(jwt_mac.status(), IsOk());

  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  EXPECT_TRUE(raw_jwt->HasTypeHeader());
  EXPECT_THAT(raw_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator.status(), IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(*compact, *validator,
                                            /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt.status(), IsOk());
  EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

  util::StatusOr<JwtValidator> validator2 =
      JwtValidatorBuilder().ExpectIssuer("unknown").Build();
  ASSERT_THAT(validator2.status(), IsOk());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid(*compact, *validator2,
                                               /*kid=*/absl::nullopt)
                   .ok());
}

TEST(JwtMacImplTest, CreateAndValidateTokenWithKid) {
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac = CreateJwtMac();
  ASSERT_THAT(jwt_mac.status(), IsOk());

  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());
  EXPECT_TRUE(raw_jwt->HasTypeHeader());
  EXPECT_THAT(raw_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncodeWithKid(*raw_jwt, "kid-123");
  ASSERT_THAT(compact.status(), IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator.status(), IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(*compact, *validator,
                                            /*kid=*/"kid-123");
  ASSERT_THAT(verified_jwt.status(), IsOk());
  EXPECT_THAT(verified_jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(verified_jwt->GetJwtId(), IsOkAndHolds("id123"));

  // with kid=absl::nullopt, the kid header in the token is ignored.
  EXPECT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(*compact, *validator,
                                              /*kid=*/absl::nullopt)
                  .status(),
              IsOk());

  // with a different kid, the verification fails.
  EXPECT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(*compact, *validator,
                                              /*kid=*/"other-kid")
                  .status(),
              Not(IsOk()));

  // parse header to make sure the kid value is set correctly.
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header.status(), IsOk());
  EXPECT_THAT(header->fields().find("kid")->second.string_value(),
              Eq("kid-123"));
}

TEST(JwtMacImplTest, ValidateFixedToken) {
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac = CreateJwtMac();
  ASSERT_THAT(jwt_mac.status(), IsOk());

  // token that expired in 2011
  std::string compact =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH"
      "AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  util::StatusOr<JwtValidator> validator_1970 =
      JwtValidatorBuilder()
          .ExpectTypeHeader("JWT")
          .ExpectIssuer("joe")
          .SetFixedNow(absl::FromUnixSeconds(12345))
          .Build();
  ASSERT_THAT(validator_1970.status(), IsOk());

  // verification succeeds because token was valid 1970
  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(compact, *validator_1970,
                                            /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt.status(), IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("joe"));
  EXPECT_THAT(verified_jwt->GetBooleanClaim("http://example.com/is_root"),
              IsOkAndHolds(true));

  // verification fails because token is expired
  util::StatusOr<JwtValidator> validator_now = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_now.status(), IsOk());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid(compact, *validator_now,
                                               /*kid=*/absl::nullopt)
                   .ok());

  // verification fails because token was modified
  std::string modified_compact =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH"
      "AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXi";
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid(
                       modified_compact, *validator_1970, /*kid=*/absl::nullopt)
                   .ok());
}

TEST(JwtMacImplTest, ValidateInvalidTokens) {
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac = CreateJwtMac();
  ASSERT_THAT(jwt_mac.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator.status(), IsOk());

  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30.abc.",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9?.e30.abc",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30?.abc",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30.abc?",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
  EXPECT_FALSE((*jwt_mac)
                   ->VerifyMacAndDecodeWithKid("eyJhbGciOiJIUzI1NiJ9.e30",
                                               *validator,
                                               /*kid=*/absl::nullopt)
                   .ok());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
