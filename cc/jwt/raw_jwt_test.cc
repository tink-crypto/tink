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

#include "tink/jwt/raw_jwt.h"

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "tink/jwt/jwt_names.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;

namespace crypto {
namespace tink {

TEST(RawJwt, GetIssuerSubjectJwtIdOK) {
  auto jwt_or = RawJwtBuilder()
                    .SetIssuer("issuer")
                    .SetSubject("subject")
                    .SetJwtId("jwt_id")
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasIssuer());
  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_TRUE(jwt.HasSubject());
  EXPECT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  EXPECT_TRUE(jwt.HasJwtId());
  EXPECT_THAT(jwt.GetJwtId(), IsOkAndHolds("jwt_id"));
}

TEST(RawJwt, TimestampsOK) {
  absl::Time now = absl::Now();
  auto jwt_or = RawJwtBuilder()
                    .SetNotBefore(now - absl::Seconds(300))
                    .SetIssuedAt(now)
                    .SetExpiration(now + absl::Seconds(300))
                    .Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_TRUE(jwt.HasNotBefore());
  auto nbf_or = jwt.GetNotBefore();
  ASSERT_THAT(nbf_or.status(), IsOk());
  auto nbf = nbf_or.ValueOrDie();
  EXPECT_LT(nbf, now - absl::Seconds(299));
  EXPECT_GT(nbf, now - absl::Seconds(301));

  EXPECT_TRUE(jwt.HasIssuedAt());
  auto iat_or = jwt.GetIssuedAt();
  ASSERT_THAT(iat_or.status(), IsOk());
  auto iat = iat_or.ValueOrDie();
  EXPECT_LT(iat, now + absl::Seconds(1));
  EXPECT_GT(iat, now - absl::Seconds(1));

  EXPECT_TRUE(jwt.HasExpiration());
  auto exp_or = jwt.GetExpiration();
  ASSERT_THAT(exp_or.status(), IsOk());
  auto exp = exp_or.ValueOrDie();
  EXPECT_LT(exp, now + absl::Seconds(301));
  EXPECT_GT(exp, now + absl::Seconds(299));
}

TEST(RawJwt, EmptyGetIssuerSubjectJwtIdNotOK) {
  auto jwt_or = RawJwtBuilder().Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  EXPECT_FALSE(jwt.HasIssuer());
  EXPECT_FALSE(jwt.GetIssuer().ok());
  EXPECT_FALSE(jwt.HasSubject());
  EXPECT_FALSE(jwt.GetSubject().ok());
  EXPECT_FALSE(jwt.HasJwtId());
  EXPECT_FALSE(jwt.GetJwtId().ok());
  EXPECT_FALSE(jwt.HasExpiration());
  EXPECT_FALSE(jwt.GetExpiration().ok());
  EXPECT_FALSE(jwt.HasNotBefore());
  EXPECT_FALSE(jwt.GetNotBefore().ok());
  EXPECT_FALSE(jwt.HasIssuedAt());
  EXPECT_FALSE(jwt.GetIssuedAt().ok());
}

TEST(RawJwt, BuildCanBeCalledTwice) {
  auto builder = RawJwtBuilder().SetIssuer("issuer").SetSubject("subject");
  auto jwt_or = builder.Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  builder.SetSubject("subject2");
  auto jwt2_or = builder.Build();
  ASSERT_THAT(jwt2_or.status(), IsOk());
  auto jwt2 = jwt2_or.ValueOrDie();

  EXPECT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  EXPECT_THAT(jwt2.GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_THAT(jwt2.GetSubject(), IsOkAndHolds("subject2"));
}

TEST(RawJwt, FromString) {
  auto jwt_or =
      RawJwt::FromString(R"({"iss":"issuer", "sub":"subject", "exp":123})");
  ASSERT_THAT(jwt_or.status(), IsOk());
  RawJwt jwt = jwt_or.ValueOrDie();

  ASSERT_THAT(jwt.GetIssuer(), IsOkAndHolds("issuer"));
  ASSERT_THAT(jwt.GetSubject(), IsOkAndHolds("subject"));
  ASSERT_THAT(jwt.GetExpiration(), IsOkAndHolds(absl::FromUnixSeconds(123)));
}

TEST(RawJwt, ToString) {
  auto jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = jwt_or.ValueOrDie();

  ASSERT_THAT(jwt.ToString(), IsOkAndHolds(R"({"iss":"issuer"})"));
}

}  // namespace tink
}  // namespace crypto
