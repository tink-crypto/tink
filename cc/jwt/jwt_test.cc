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

#include "tink/jwt/jwt.h"

#include "gtest/gtest.h"
#include "tink/jwt/json_struct_util.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;

namespace crypto {
namespace tink {

class JwtTest : public ::testing::Test {
 public:
  util::StatusOr<std::unique_ptr<Jwt>> wrapFriendNew(
      const google::protobuf::Struct& header,
      const google::protobuf::Struct& payload, const absl::Time clock,
      const absl::Duration clockSkew) {
    return Jwt::New(header, payload, clock, clockSkew);
  }
  util::Status wrapFriendValidateTimestampClaims(const Jwt& jwt) {
    return jwt.validateTimestampClaims();
  }
};

TEST_F(JwtTest, InvalidFieldTypeInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "bla";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["iss"] = 12345;

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetIssuer().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, UnknownClaimNotFound) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["claim1"] = "John Doe";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsNumber("unknown").status(),
              StatusIs(util::error::NOT_FOUND));
}

TEST_F(JwtTest, CustomStringClaimOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = "John Doe";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsString("custom"), IsOkAndHolds("John Doe"));
}

TEST_F(JwtTest, CustomEmptyStringClaimOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = "";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsString("custom"), IsOkAndHolds(""));
}

TEST_F(JwtTest, CustomEmptyNumberClaimInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = "";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsNumber("custom").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, CustomEmptyBoolClaimInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = "";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsBool("custom").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, CustomUnsignedClaimOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = static_cast<double>(123456U);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsNumber("custom"), IsOkAndHolds(123456U));
}

TEST_F(JwtTest, CustomSignedClaimOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = -123456;

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsNumber("custom"), IsOkAndHolds(-123456));
}

TEST_F(JwtTest, CustomSignedClaim2Ok) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = 123456;

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsNumber("custom"), IsOkAndHolds(123456));
}

TEST_F(JwtTest, CustomMixedListClaimInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"].append(1);
  bpayload["custom"].append("bla");

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsNumber("custom").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetClaimAsString("custom").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetClaimAsBool("custom").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetClaimAsNumberList("custom").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetClaimAsStringList("custom").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, CustomStringListClaimOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"].append("a");
  bpayload["custom"].append("bla");

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  auto claim_or = jwt->GetClaimAsStringList("custom");
  ASSERT_THAT(claim_or.status(), IsOk());
  auto claim = claim_or.ValueOrDie();
  ASSERT_EQ(claim.size(), 2);
  ASSERT_EQ(claim[0], "a");
  ASSERT_EQ(claim[1], "bla");
}

TEST_F(JwtTest, CustomNumberListClaimOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"].append(123);
  bpayload["custom"].append(456);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  auto claim_or = jwt->GetClaimAsNumberList("custom");
  ASSERT_THAT(claim_or.status(), IsOk());
  auto claim = claim_or.ValueOrDie();
  ASSERT_EQ(claim.size(), 2);
  ASSERT_EQ(claim[0], 123);
  ASSERT_EQ(claim[1], 456);
}

TEST_F(JwtTest, CustomUnsignedClaimInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = "a string";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsNumber("custom").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, CustomBoolClaimOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["alg"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["custom"] = true;

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetClaimAsBool("custom"), IsOkAndHolds(true));
}

TEST_F(JwtTest, TestAlgorithmOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["alg"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["bla"] = "...";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetAlgorithm(), IsOkAndHolds("HS256"));
}

TEST_F(JwtTest, TestTypeOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["typ"] = "JWT";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["bla"] = "...";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetType(), IsOkAndHolds("JWT"));
}

TEST_F(JwtTest, TestContentType_Ok) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["cty"] = "JWT";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["bla"] = "...";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetContentType(), IsOkAndHolds("JWT"));
}

TEST_F(JwtTest, TestKeyIdStringOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["kid"] = "the-key-012345";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["bla"] = "...";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetKeyId(), IsOkAndHolds("the-key-012345"));
}

TEST_F(JwtTest, TestIssuerOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["iss"] = "the issuer";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetIssuer(), IsOkAndHolds("the issuer"));
}

TEST_F(JwtTest, TestSubjectOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["sub"] = "the subject";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetSubject(), IsOkAndHolds("the subject"));
}

TEST_F(JwtTest, TestJwtIdOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["jti"] = "the ID";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetJwtId(), IsOkAndHolds("the ID"));
}

TEST_F(JwtTest, TestAudienceInvalidArgument1) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["aud"] = 123456;

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  auto aud_or = jwt->GetAudiences();
  ASSERT_THAT(aud_or.status(), StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, TestAudienceInvalidArgument2) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["aud"].append(1234);
  bpayload["aud"].append(5678);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  auto aud_or = jwt->GetAudiences();
  ASSERT_THAT(aud_or.status(), StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, TestOneAudienceOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["aud"] = "my audience";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  auto aud_or = jwt->GetAudiences();
  ASSERT_THAT(aud_or.status(), IsOk());
  auto aud_vec = std::move(aud_or.ValueOrDie());
  ASSERT_EQ(aud_vec.size(), 1);
  ASSERT_EQ(aud_vec[0], "my audience");
}

TEST_F(JwtTest, TestTwoAudienceOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["aud"].append("aud1");
  bpayload["aud"].append("aud2");

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  auto aud_or = jwt->GetAudiences();
  ASSERT_THAT(aud_or.status(), IsOk());
  auto aud_vec = std::move(aud_or.ValueOrDie());
  ASSERT_EQ(aud_vec.size(), 2);
  ASSERT_EQ(aud_vec[0], "aud1");
  ASSERT_EQ(aud_vec[1], "aud2");
}

TEST_F(JwtTest, TestUnsignedExpirationOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["exp"] = (1483228800);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetExpiration(),
              IsOkAndHolds(absl::FromUnixSeconds(1483228800)));
}

TEST_F(JwtTest, TestUnsignedNotBeforeOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["nbf"] = (1483228800);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetNotBefore(),
              IsOkAndHolds(absl::FromUnixSeconds(1483228800)));
}

TEST_F(JwtTest, TestUnsignedIssuedAtOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["iat"] = (1483228800);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetIssuedAt(),
              IsOkAndHolds(absl::FromUnixSeconds(1483228800)));
}

TEST_F(JwtTest, TestSignedExpirationOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["exp"] = (-1483228800);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetExpiration(),
              IsOkAndHolds(absl::FromUnixSeconds(-1483228800)));
}

TEST_F(JwtTest, TestStringNotBeforeInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["nbf"] = "12345";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetNotBefore().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, TestStringIssuedAtInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["iat"] = "12345";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetIssuedAt().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, TestStringExpirationInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["exp"] = "12345";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetExpiration().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, TestSignedIssuedAtOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["iat"] = (-1483228800);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetIssuedAt(),
              IsOkAndHolds(absl::FromUnixSeconds(-1483228800)));
}

TEST_F(JwtTest, TestExpiration1Ok) {
  absl::Time now = absl::Now();

  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["exp"] = static_cast<double>(absl::ToUnixSeconds(now));

  auto jwt_or =
      wrapFriendNew(header, payload, now + absl::Minutes(5), absl::Minutes(6));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(wrapFriendValidateTimestampClaims(*jwt), IsOk());
}

TEST_F(JwtTest, TestNotBefore1Ok) {
  absl::Time now = absl::Now();

  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["nbf"] = static_cast<double>(absl::ToUnixSeconds(now));

  auto jwt_or =
      wrapFriendNew(header, payload, now - absl::Minutes(5), absl::Minutes(6));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(wrapFriendValidateTimestampClaims(*jwt), IsOk());
}

TEST_F(JwtTest, TestNotBefore2Ok) {
  absl::Time now = absl::Now();

  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["nbf"] = static_cast<double>(absl::ToUnixSeconds(now));

  auto jwt_or =
      wrapFriendNew(header, payload, now - absl::Minutes(5), absl::Minutes(5));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(wrapFriendValidateTimestampClaims(*jwt), IsOk());
}

TEST_F(JwtTest, TestNotBeforeOutOfRange) {
  absl::Time now = absl::Now();

  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["nbf"] = static_cast<double>(absl::ToUnixSeconds(now));

  auto jwt_or =
      wrapFriendNew(header, payload, now - absl::Minutes(5), absl::Minutes(4));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(wrapFriendValidateTimestampClaims(*jwt),
              StatusIs(util::error::OUT_OF_RANGE));
}

TEST_F(JwtTest, TestValidateTimestampsNoExpirationOrNotBeforeOk) {
  absl::Time now = absl::Now();

  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["bla"] = static_cast<double>(absl::ToUnixSeconds(now));

  auto jwt_or =
      wrapFriendNew(header, payload, now - absl::Minutes(5), absl::Minutes(6));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(wrapFriendValidateTimestampClaims(*jwt), IsOk());
}

TEST_F(JwtTest, AllFieldsInvalidTypeInvalidArguments) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["alg"] = 1234;
  bheader["typ"] = 123;
  bheader["kid"] = "the-key-012345";
  bheader["cty"] = 123;

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["name"] = "John Doe";
  bpayload["sub"] = 1234;
  bpayload["iat"].append(1);  // iat = [1,2,3,4]
  bpayload["iat"].append(2);
  bpayload["iat"].append(3);
  bpayload["iat"].append(4);
  bpayload["nbf"].append(1);  // nbf = [1,2,3]
  bpayload["nbf"].append(2);
  bpayload["nbf"].append(3);
  bpayload["exp"].append(1);  // exp = [1,2,3]
  bpayload["exp"].append(2);
  bpayload["exp"].append(3);
  bpayload["iss"] = 1234;
  bpayload["aud"] = 1234;
  bpayload["jti"] = 1234;

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetAlgorithm().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetType().status(), StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetContentType().status(),
              StatusIs(util::error::INVALID_ARGUMENT));

  ASSERT_THAT(jwt->GetExpiration().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetIssuedAt().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetNotBefore().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetIssuer().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetSubject().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetJwtId().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt->GetAudiences().status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, StandardOneAudienceOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["alg"] = "HS256";
  bheader["typ"] = "JWT";
  bheader["kid"] = "the-key-012345";
  bheader["cty"] = "JWT";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["name"] = "John Doe";
  bpayload["sub"] = "the subject";
  bpayload["iat"] = 1516239022;
  bpayload["nbf"] = 1483228801;
  bpayload["exp"] = 1483228800;
  bpayload["iss"] = "issuer-google";
  bpayload["aud"] = "my audience";
  bpayload["jti"] = "the ID";

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetAlgorithm(), IsOkAndHolds("HS256"));
  ASSERT_THAT(jwt->GetType(), IsOkAndHolds("JWT"));
  ASSERT_THAT(jwt->GetContentType(), IsOkAndHolds("JWT"));

  ASSERT_THAT(jwt->GetIssuer(), IsOkAndHolds("issuer-google"));
  ASSERT_THAT(jwt->GetSubject(), IsOkAndHolds("the subject"));
  ASSERT_THAT(jwt->GetJwtId(), IsOkAndHolds("the ID"));
  ASSERT_THAT(jwt->GetKeyId(), IsOkAndHolds("the-key-012345"));

  ASSERT_THAT(jwt->GetExpiration(),
              IsOkAndHolds(absl::FromUnixSeconds(1483228800)));
  ASSERT_THAT(jwt->GetNotBefore(),
              IsOkAndHolds(absl::FromUnixSeconds(1483228801)));
  ASSERT_THAT(jwt->GetIssuedAt(),
              IsOkAndHolds(absl::FromUnixSeconds(1516239022)));

  auto aud_or = jwt->GetAudiences();
  ASSERT_THAT(aud_or.status(), IsOk());
  auto aud_vec = std::move(aud_or.ValueOrDie());
  ASSERT_EQ(aud_vec.size(), 1);
  ASSERT_EQ(aud_vec[0], "my audience");
}

TEST_F(JwtTest, TwoAudiencesOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["alg"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["aud"].append("aud2");
  bpayload["aud"].append("aud1");

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  auto aud_or = jwt->GetAudiences();
  ASSERT_THAT(aud_or.status(), IsOk());
  auto aud_vec = std::move(aud_or.ValueOrDie());
  ASSERT_EQ(aud_vec.size(), 2);
  ASSERT_EQ(aud_vec[0], "aud2");
  ASSERT_EQ(aud_vec[1], "aud1");
}

TEST_F(JwtTest, MixedAudiencesInvalidArgument) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["alg"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["aud"].append(1);
  bpayload["aud"].append("bla");

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  auto aud_or = jwt->GetAudiences();
  ASSERT_THAT(aud_or.status(), StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(JwtTest, SignedNotBeforeOk) {
  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["nbf"] = static_cast<double>(-1483228800);

  auto jwt_or = wrapFriendNew(header, payload, absl::Now(), absl::Minutes(10));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(jwt->GetNotBefore(),
              IsOkAndHolds(absl::FromUnixSeconds(-1483228800)));
}

TEST_F(JwtTest, ExpirationOutOfRange) {
  absl::Time now = absl::Now();

  google::protobuf::Struct header;
  JsonStructBuilder bheader(&header);
  bheader["bla"] = "HS256";

  google::protobuf::Struct payload;
  JsonStructBuilder bpayload(&payload);
  bpayload["nbf"] = static_cast<double>(absl::ToUnixSeconds(now));

  auto jwt_or =
      wrapFriendNew(header, payload, now - absl::Minutes(5), absl::Minutes(4));
  ASSERT_THAT(jwt_or.status(), IsOk());
  auto jwt = std::move(jwt_or.ValueOrDie());

  ASSERT_THAT(wrapFriendValidateTimestampClaims(*jwt),
              StatusIs(util::error::OUT_OF_RANGE));
}

}  // namespace tink
}  // namespace crypto
