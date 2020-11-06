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

#include "tink/jwt/jwt_object.h"

#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/escaping.h"
#include "tink/jwt/json_field_types.h"
#include "tink/jwt/jwt_names.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::Pair;

namespace crypto {
namespace tink {

TEST(JwtObject, TypeOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetType("xxx"), IsOk());
  ASSERT_THAT(jwt.SetType("the type"), IsOk());

  ASSERT_THAT(jwt.GetType(), IsOkAndHolds("the type"));
}

TEST(JwtObject, ContentTypeOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetContentType("xxx"), IsOk());
  ASSERT_THAT(jwt.SetContentType("the type"), IsOk());

  ASSERT_THAT(jwt.GetContentType(), IsOkAndHolds("the type"));
}

TEST(JwtObject, AlgorithmHS256OK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetAlgorithm(JwtAlgorithm::kEs256), IsOk());
  ASSERT_THAT(jwt.SetAlgorithm(JwtAlgorithm::kHs256), IsOk());

  ASSERT_THAT(jwt.GetAlgorithm(), IsOkAndHolds(JwtAlgorithm::kHs256));
}

TEST(JwtObject, AlgorithmES256OK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetAlgorithm(JwtAlgorithm::kRs256), IsOk());
  ASSERT_THAT(jwt.SetAlgorithm(JwtAlgorithm::kEs256), IsOk());

  ASSERT_THAT(jwt.GetAlgorithm(), IsOkAndHolds(JwtAlgorithm::kEs256));
}

TEST(JwtObject, AlgorithmRS256OK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetAlgorithm(JwtAlgorithm::kEs256), IsOk());
  ASSERT_THAT(jwt.SetAlgorithm(JwtAlgorithm::kRs256), IsOk());

  ASSERT_THAT(jwt.GetAlgorithm(), IsOkAndHolds(JwtAlgorithm::kRs256));
}

TEST(JwtObject, KeyidOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetKeyId("key-xxx"), IsOk());
  ASSERT_THAT(jwt.SetKeyId("key-id1234"), IsOk());

  ASSERT_THAT(jwt.GetKeyId(), IsOkAndHolds("key-id1234"));
}

TEST(JwtObject, IssuerOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);
  ASSERT_THAT(jwt.SetIssuer("xxx"), IsOk());
  ASSERT_THAT(jwt.SetIssuer("google"), IsOk());

  ASSERT_THAT(jwt.GetIssuer(), IsOkAndHolds("google"));
}

TEST(JwtObject, SubjectOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetSubject("xxx"), IsOk());
  ASSERT_THAT(jwt.SetSubject("google"), IsOk());

  ASSERT_THAT(jwt.GetSubject(), IsOkAndHolds("google"));
}

TEST(JwtObject, JwtIdOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetJwtId("xxx"), IsOk());
  ASSERT_THAT(jwt.SetJwtId("google"), IsOk());

  ASSERT_THAT(jwt.GetJwtId(), IsOkAndHolds("google"));
}

TEST(JwtObject, ExpirationOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  absl::Time now = absl::Now();
  ASSERT_THAT(jwt.SetExpiration(now + absl::Seconds(300)), IsOk());
  ASSERT_THAT(jwt.SetExpiration(now), IsOk());

  auto value_or = jwt.GetExpiration();
  ASSERT_THAT(value_or.status(), IsOk());
  auto value = value_or.ValueOrDie();
  ASSERT_LT(value, now + absl::Seconds(1));
  ASSERT_GT(value, now - absl::Seconds(1));
}

TEST(JwtObject, NotBeforeOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  absl::Time now = absl::Now();
  ASSERT_THAT(jwt.SetNotBefore(now + absl::Seconds(300)), IsOk());
  ASSERT_THAT(jwt.SetNotBefore(now), IsOk());

  auto value_or = jwt.GetNotBefore();
  ASSERT_THAT(value_or.status(), IsOk());
  auto value = value_or.ValueOrDie();
  ASSERT_LT(value, now + absl::Seconds(1));
  ASSERT_GT(value, now - absl::Seconds(1));
}

TEST(JwtObject, IssuedAtOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  absl::Time now = absl::Now();
  ASSERT_THAT(jwt.SetIssuedAt(now + absl::Seconds(300)), IsOk());
  ASSERT_THAT(jwt.SetIssuedAt(now), IsOk());

  auto value_or = jwt.GetIssuedAt();
  ASSERT_THAT(value_or.status(), IsOk());
  auto value = value_or.ValueOrDie();
  ASSERT_LT(value, now + absl::Seconds(1));
  ASSERT_GT(value, now - absl::Seconds(1));
}

TEST(JwtObject, AudiencesOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);
  ASSERT_THAT(jwt.AddAudience("aud1"), IsOk());
  ASSERT_THAT(jwt.AddAudience("aud2"), IsOk());
  ASSERT_THAT(jwt.AddAudience("aud3"), IsOk());

  auto value_or = jwt.GetAudiences();
  std::vector<std::string> list = {"aud1", "aud2", "aud3"};
  ASSERT_THAT(jwt.GetAudiences(), IsOkAndHolds(list));
}

TEST(JwtObject, ListHeaderNameAndTypesOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  // Header fields.
  ASSERT_THAT(jwt.SetAlgorithm(JwtAlgorithm::kEs256), IsOk());
  ASSERT_THAT(jwt.SetKeyId("key-xxx"), IsOk());
  ASSERT_THAT(jwt.SetContentType("xxx"), IsOk());
  ASSERT_THAT(jwt.SetType("xxx"), IsOk());

  auto headers_or = jwt.getHeaderNamesAndTypes();
  ASSERT_THAT(headers_or.status(), IsOk());
  absl::flat_hash_map<std::string, enum JsonFieldType> headers =
      headers_or.ValueOrDie();

  EXPECT_THAT(headers,
              testing::UnorderedElementsAre(
                  Pair(kJwtHeaderAlgorithm, JsonFieldType::kString),
                  Pair(kJwtHeaderType, JsonFieldType::kString),
                  Pair(kJwtHeaderContentType, JsonFieldType::kString),
                  Pair(kJwtHeaderKeyId, JsonFieldType::kString)));
}

TEST(JwtObject, ListClaimNameAndTypesOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  // Payload claims.
  ASSERT_THAT(jwt.AddAudience("aud1"), IsOk());
  ASSERT_THAT(jwt.AddAudience("aud2"), IsOk());
  ASSERT_THAT(jwt.AddAudience("aud3"), IsOk());
  ASSERT_THAT(jwt.SetClaimAsString("sClaim", "xxx"), IsOk());
  ASSERT_THAT(jwt.SetClaimAsNumber("nClaim", 123), IsOk());
  ASSERT_THAT(jwt.SetClaimAsBool("bClaim", true), IsOk());
  ASSERT_THAT(jwt.SetSubject("xxx"), IsOk());
  ASSERT_THAT(jwt.SetIssuer("xxx"), IsOk());
  absl::Time now = absl::Now();
  ASSERT_THAT(jwt.SetIssuedAt(now), IsOk());
  ASSERT_THAT(jwt.SetNotBefore(now), IsOk());
  ASSERT_THAT(jwt.SetExpiration(now), IsOk());

  auto claims_or = jwt.getClaimNamesAndTypes();
  ASSERT_THAT(claims_or.status(), IsOk());
  absl::flat_hash_map<std::string, enum JsonFieldType> claims =
      claims_or.ValueOrDie();
  EXPECT_THAT(claims,
              testing::UnorderedElementsAre(
                  Pair(kJwtClaimAudience, JsonFieldType::kStringList),
                  Pair("sClaim", JsonFieldType::kString),
                  Pair("nClaim", JsonFieldType::kNumber),
                  Pair("bClaim", JsonFieldType::kBool),
                  Pair(kJwtClaimSubject, JsonFieldType::kString),
                  Pair(kJwtClaimIssuer, JsonFieldType::kString),
                  Pair(kJwtClaimIssuedAt, JsonFieldType::kNumber),
                  Pair(kJwtClaimNotBefore, JsonFieldType::kNumber),
                  Pair(kJwtClaimExpiration, JsonFieldType::kNumber)));
}

TEST(JwtObject, ClaimStringOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetClaimAsString("claim1", "xxx"), IsOk());
  ASSERT_THAT(jwt.SetClaimAsString("claim1", "bla"), IsOk());

  ASSERT_THAT(jwt.GetClaimAsString("claim1"), IsOkAndHolds("bla"));
}

TEST(JwtObject, ClaimNumberOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);
  ASSERT_THAT(jwt.SetClaimAsNumber("claim1", 567), IsOk());
  ASSERT_THAT(jwt.SetClaimAsNumber("claim1", 123), IsOk());

  ASSERT_THAT(jwt.GetClaimAsNumber("claim1"), IsOkAndHolds(123));
}

TEST(JwtObject, ClaimListNumberOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);
  std::vector<int> nvalues = {1, 2};

  for (auto &v : nvalues) {
    ASSERT_THAT(jwt.AppendClaimToNumberList("claim1", v), IsOk());
  }

  std::vector<int> nvalues3 = {1, 2};
  ASSERT_THAT(jwt.GetClaimAsNumberList("claim1"), IsOkAndHolds(nvalues3));
}

TEST(JwtObject, ClaimListStringOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  std::vector<absl::string_view> nvalues = {"he", "ho"};
  for (auto &v : nvalues) {
    ASSERT_THAT(jwt.AppendClaimToStringList("claim1", v), IsOk());
  }

  std::vector<std::string> nvalues2 = {"he", "ho"};
  ASSERT_THAT(jwt.GetClaimAsStringList("claim1"), IsOkAndHolds(nvalues2));
}

TEST(JwtObject, ClaimBoolOK) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  ASSERT_THAT(jwt.SetClaimAsBool("claim1", true), IsOk());
  ASSERT_THAT(jwt.GetClaimAsBool("claim1"), IsOkAndHolds(true));

  ASSERT_THAT(jwt.SetClaimAsBool("claim1", false), IsOk());
  ASSERT_THAT(jwt.GetClaimAsBool("claim1"), IsOkAndHolds(false));
}

TEST(JwtObject, AddRegisteredClaimInvalidArgument) {
  JsonObject header;
  JsonObject payload;
  auto jwt = JwtObject(header, payload);

  std::string value = "bla";
  ASSERT_THAT(jwt.SetClaimAsString("iss", value),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsString("sub", value),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsString("aud", value),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsString("exp", value),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsString("nbf", value),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsString("iat", value),
              StatusIs(util::error::INVALID_ARGUMENT));

  ASSERT_THAT(jwt.SetClaimAsNumber("iss", 123),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsNumber("sub", 123),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsNumber("aud", 123),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsNumber("exp", 123),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsNumber("nbf", 123),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsNumber("iat", 123),
              StatusIs(util::error::INVALID_ARGUMENT));

  ASSERT_THAT(jwt.SetClaimAsBool("iss", true),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsBool("sub", true),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsBool("aud", true),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsBool("exp", true),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsBool("nbf", true),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(jwt.SetClaimAsBool("iat", true),
              StatusIs(util::error::INVALID_ARGUMENT));

  std::vector<absl::string_view> svalues = {"ha", "be"};
  for (auto &v : svalues) {
    ASSERT_THAT(jwt.AppendClaimToStringList("iss", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToStringList("sub", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToStringList("aud", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToStringList("exp", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToStringList("nbf", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToStringList("iat", v),
                StatusIs(util::error::INVALID_ARGUMENT));
  }

  std::vector<int> nvalues = {1, 2};
  for (auto &v : nvalues) {
    ASSERT_THAT(jwt.AppendClaimToNumberList("iss", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToNumberList("sub", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToNumberList("aud", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToNumberList("exp", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToNumberList("nbf", v),
                StatusIs(util::error::INVALID_ARGUMENT));
    ASSERT_THAT(jwt.AppendClaimToNumberList("iat", v),
                StatusIs(util::error::INVALID_ARGUMENT));
  }
}

}  // namespace tink
}  // namespace crypto
