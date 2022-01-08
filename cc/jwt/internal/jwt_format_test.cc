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

#include "tink/jwt/internal/jwt_format.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::OutputPrefixType;
using testing::Eq;

namespace crypto {
namespace tink {
namespace jwt_internal {

TEST(JwtFormat, EncodeDecodeHeader) {
  std::string header = R"({"alg":"HS256"})";
  std::string output;
  ASSERT_TRUE(DecodeHeader(EncodeHeader(header), &output));
  EXPECT_THAT(output, Eq(header));
}

TEST(JwtFormat, EncodeFixedHeader) {
  // Null-terminted example from https://tools.ietf.org/html/rfc7519#section-3.1
  char header[] = {123, 34, 116, 121, 112, 34, 58, 34, 74,  87,
                   84,  34, 44,  13,  10,  32, 34, 97, 108, 103,
                   34,  58, 34,  72,  83,  50, 53, 54, 34,  125, 0};
  EXPECT_THAT(EncodeHeader(header),
              Eq("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"));
}

TEST(JwtFormat, DecodedHeaderWithLineFeedFails) {
  std::string output;
  ASSERT_FALSE(
      DecodeHeader("eyJ0eXAiOiJKV1Qi\nLA0KICJhbGciOiJIUzI1NiJ9", &output));
}

TEST(JwtFormat, EncodeDecodePayload) {
  std::string payload = R"({"iss":"issuer"})";
  std::string output;
  ASSERT_TRUE(DecodePayload(EncodePayload(payload), &output));
  EXPECT_THAT(output, Eq(payload));
}

TEST(JwtFormat, EncodeFixedPayload) {
  // Null-terminted example from https://tools.ietf.org/html/rfc7519#section-3.1
  char payload[] = {123, 34,  105, 115, 115, 34,  58,  34,  106, 111, 101, 34,
                    44,  13,  10,  32,  34,  101, 120, 112, 34,  58,  49,  51,
                    48,  48,  56,  49,  57,  51,  56,  48,  44,  13,  10,  32,
                    34,  104, 116, 116, 112, 58,  47,  47,  101, 120, 97,  109,
                    112, 108, 101, 46,  99,  111, 109, 47,  105, 115, 95,  114,
                    111, 111, 116, 34,  58,  116, 114, 117, 101, 125, 0};
  EXPECT_THAT(EncodeHeader(payload),
              Eq("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0"
                          "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"));
}

TEST(JwtFormat, DecodeInvalidPayload_fails) {
  std::string output;
  ASSERT_FALSE(DecodePayload("eyJmb28iO?JiYXIifQ", &output));
}

TEST(JwtFormat, DecodeAndValidateFixedHeaderHS256) {
  // Example from https://tools.ietf.org/html/rfc7515#appendix-A.1
  std::string encoded_header = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

  std::string json_header;
  ASSERT_TRUE(DecodeHeader(encoded_header, &json_header));
  EXPECT_THAT(json_header, Eq("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"));

  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());

  EXPECT_THAT(ValidateHeader(*header, "HS256", absl::nullopt, absl::nullopt),
              IsOk());
  EXPECT_FALSE(
      ValidateHeader(*header, "RS256", absl::nullopt, absl::nullopt).ok());
}

TEST(JwtFormat, DecodeAndValidateFixedHeaderRS256) {
  // Example from https://tools.ietf.org/html/rfc7515#appendix-A.2
  std::string encoded_header = "eyJhbGciOiJSUzI1NiJ9";

  std::string json_header;
  ASSERT_TRUE(DecodeHeader(encoded_header, &json_header));
  EXPECT_THAT(json_header, Eq(R"({"alg":"RS256"})"));

  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());

  EXPECT_THAT(ValidateHeader(*header, "RS256", absl::nullopt, absl::nullopt),
              IsOk());
  EXPECT_FALSE(
      ValidateHeader(*header, "HS256", absl::nullopt, absl::nullopt).ok());
}

TEST(JwtFormat, CreateValidateHeader) {
  util::StatusOr<std::string> encoded_header =
      CreateHeader("PS384", absl::nullopt, absl::nullopt);
  EXPECT_THAT(encoded_header.status(), IsOk());

  std::string json_header;
  ASSERT_TRUE(DecodeHeader(*encoded_header, &json_header));

  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());

  EXPECT_THAT(ValidateHeader(*header, "PS384", absl::nullopt, absl::nullopt),
              IsOk());
  EXPECT_FALSE(
      ValidateHeader(*header, "HS256", absl::nullopt, absl::nullopt).ok());
}

TEST(JwtFormat, CreateValidateHeaderWithTypeAndKid) {
  util::StatusOr<std::string> encoded_header =
      CreateHeader("PS384", "JWT", "kid-1234");
  EXPECT_THAT(encoded_header.status(), IsOk());

  std::string json_header;
  ASSERT_TRUE(DecodeHeader(*encoded_header, &json_header));

  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());

  EXPECT_THAT(GetTypeHeader(*header), Eq("JWT"));
  EXPECT_THAT(ValidateHeader(*header, "PS384", absl::nullopt, absl::nullopt),
              IsOk());
  EXPECT_FALSE(
      ValidateHeader(*header, "HS256", absl::nullopt, absl::nullopt).ok());

  auto it = header->fields().find("kid");
  EXPECT_FALSE(it == header->fields().end());
  const google::protobuf::Value& value = it->second;
  EXPECT_THAT(value.kind_case(), Eq(google::protobuf::Value::kStringValue));
  EXPECT_THAT(value.string_value(), Eq("kid-1234"));
}

TEST(JwtFormat, ValidateEmptyHeaderFails) {
  google::protobuf::Struct empty_header;
  EXPECT_FALSE(
      ValidateHeader(empty_header, "HS256", absl::nullopt, absl::nullopt).ok());
}

TEST(JwtFormat, ValidateHeaderWithUnknownTypeOk) {
  std::string json_header = R"({"alg":"HS256","typ":"unknown"})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());

  EXPECT_THAT(ValidateHeader(*header, "HS256", absl::nullopt, absl::nullopt),
              IsOk());
}

TEST(JwtFormat, ValidateHeaderRejectsCrit) {
  std::string json_header =
      R"({"alg":"HS256","crit":["http://example.invalid/UNDEFINED"],)"
      R"("http://example.invalid/UNDEFINED":true})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());
  EXPECT_FALSE(
      ValidateHeader(*header, "HS256", absl::nullopt, absl::nullopt).ok());
}

TEST(JwtFormat, ValidateHeaderWithUnknownEntry) {
  std::string json_header = R"({"alg":"HS256","unknown":"header"})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());
  EXPECT_THAT(ValidateHeader(*header, "HS256", absl::nullopt, absl::nullopt),
              IsOk());
}

TEST(JwtFormat, ValidateHeaderWithInvalidAlgTypFails) {
  std::string json_header = R"({"alg":true})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());
  EXPECT_FALSE(
      ValidateHeader(*header, "HS256", absl::nullopt, absl::nullopt).ok());
}

TEST(JwtFormat, ValidateHeaderWithTinkKid) {
  std::string json_header = R"({"alg":"HS256","kid":"tink_kid"})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());
  EXPECT_THAT(ValidateHeader(*header, "HS256", "tink_kid", absl::nullopt),
              IsOk());
  EXPECT_FALSE(
      ValidateHeader(*header, "HS256", "other_tink_kid", absl::nullopt).ok());
}

TEST(JwtFormat, ValidateHeaderWithTinkKidMissingFails) {
  std::string json_header = R"({"alg":"HS256"})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());
  // If tink_kid is set, then the kid is required in the header.
  EXPECT_FALSE(
      ValidateHeader(*header, "HS256", "tink_kid", absl::nullopt).ok());
}

TEST(JwtFormat, ValidateHeaderWithCustomKid) {
  std::string json_header = R"({"alg":"HS256","kid":"custom_kid"})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());
  EXPECT_THAT(ValidateHeader(*header, "HS256", absl::nullopt, "custom_kid"),
              IsOk());
  EXPECT_FALSE(
      ValidateHeader(*header, "HS256", absl::nullopt, "other_custom_kid").ok());
}

TEST(JwtFormat, ValidateHeaderWithCustomKidMissingFails) {
  std::string json_header = R"({"alg":"HS256"})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());
  // If custom_kid is set, then the kid is not required in the header.
  EXPECT_THAT(ValidateHeader(*header, "HS256", absl::nullopt, "custom_kid"),
              IsOk());
}

TEST(JwtFormat, ValidateHeaderWithTinkAndCustomKidFails) {
  std::string json_header = R"({"alg":"HS256","kid":"tink_kid"})";
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  EXPECT_THAT(header.status(), IsOk());
  EXPECT_FALSE(ValidateHeader(*header, "HS256", "kid", "kid").ok());
}

TEST(JwtFormat, GetKidWithTinkOutputPrefixType) {
  uint32_t keyId = 0x1ac6a944;
  std::string kid = "GsapRA";
  EXPECT_THAT(GetKid(keyId, OutputPrefixType::TINK), Eq(kid));
  EXPECT_THAT(GetKeyId(kid), Eq(keyId));
}

TEST(JwtFormat, GetKeyId) {
  uint32_t keyId = 0x1ac6a944;
  std::string kid = "GsapRA";
  EXPECT_THAT(GetKeyId(kid), Eq(keyId));
}

TEST(JwtFormat, GetKidWithRawOutputPrefixTypeIsNotPresent) {
  uint32_t keyId = 0x1ac6a944;
  EXPECT_THAT(GetKid(keyId, OutputPrefixType::RAW), Eq(absl::nullopt));
}

TEST(JwtFormat, KeyIdKidConversion) {
  EXPECT_THAT(GetKeyId(*GetKid(0x12345678, OutputPrefixType::TINK)),
              Eq(0x12345678));
  EXPECT_THAT(GetKeyId(*GetKid(0, OutputPrefixType::TINK)), Eq(0));
  EXPECT_THAT(GetKeyId(*GetKid(100, OutputPrefixType::TINK)), Eq(100));
  EXPECT_THAT(GetKeyId(*GetKid(2147483647, OutputPrefixType::TINK)),
              Eq(2147483647));
  EXPECT_THAT(GetKeyId(*GetKid(0xffffffff, OutputPrefixType::TINK)),
              Eq(0xffffffff));
}

TEST(JwtFormat, GetKeyIdFromInvalidKidIsNotPresent) {
  EXPECT_THAT(GetKeyId(""), Eq(absl::nullopt));
  EXPECT_THAT(GetKeyId("Gsap"), Eq(absl::nullopt));
  EXPECT_THAT(GetKeyId("GsapRAAA"), Eq(absl::nullopt));
}

TEST(JwtFormat, DecodeFixedPayload) {
  // Example from https://tools.ietf.org/html/rfc7519#section-3.1
  std::string encoded_payload =
      "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0"
      "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

  std::string expected =
      "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n "
      "\"http://example.com/is_root\":true}";
  std::string output;
  ASSERT_TRUE(DecodePayload(encoded_payload, &output));
  EXPECT_THAT(output, Eq(expected));
}

TEST(JwtFormat, DecodePayloadWithLineFeedFails) {
  // A linefeed as part of the payload (as in test DecodeFixedPayload) is fine,
  // but a linefeed in the encoded payload is not.
  std::string encoded_header_with_line_feed =
      "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0\n"
      "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
  std::string output;
  ASSERT_FALSE(
      DecodePayload(encoded_header_with_line_feed, &output));
}

TEST(JwtFormat, EncodeFixedSignature) {
  std::string encoded_signature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  std::string signature;
  ASSERT_TRUE(DecodeSignature(encoded_signature, &signature));
  EXPECT_THAT(EncodeSignature(signature), Eq(encoded_signature));
}

TEST(JwtFormat, DecodeSignatureWithLineFeedFails) {
  std::string output;
  ASSERT_FALSE(
      DecodePayload("dBjftJeZ4CVP-mB92K2\n7uhbUJU1p1r_wW1gFWFOEjXk", &output));
}

TEST(RawJwt, FromJson) {
  util::StatusOr<RawJwt> jwt = RawJwtParser::FromJson(
      absl::nullopt,
      R"({"iss":"issuer", "sub":"subject", "exp":123, "aud":["a1", "a2"]})");
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_FALSE(jwt->HasTypeHeader());
  EXPECT_THAT(jwt->GetIssuer(), IsOkAndHolds("issuer"));
  EXPECT_THAT(jwt->GetSubject(), IsOkAndHolds("subject"));
  EXPECT_THAT(jwt->GetExpiration(), IsOkAndHolds(absl::FromUnixSeconds(123)));
  std::vector<std::string> expected_audiences = {"a1", "a2"};
  EXPECT_THAT(jwt->GetAudiences(), IsOkAndHolds(expected_audiences));
}

TEST(RawJwt, FromJsonWithTypeHeader) {
  util::StatusOr<RawJwt> jwt =
      RawJwtParser::FromJson("typeHeader", R"({"iss":"issuer"})");
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_THAT(jwt->GetTypeHeader(), IsOkAndHolds("typeHeader"));
  EXPECT_THAT(jwt->GetIssuer(), IsOkAndHolds("issuer"));
}

TEST(RawJwt, FromJsonExpExpiration) {
  util::StatusOr<RawJwt> jwt =
      RawJwtParser::FromJson(absl::nullopt, R"({"exp":1e10})");
  ASSERT_THAT(jwt.status(), IsOk());

  EXPECT_THAT(jwt->GetExpiration(),
              IsOkAndHolds(absl::FromUnixSeconds(10000000000)));
}

TEST(RawJwt, FromJsonExpirationTooLarge) {
  util::StatusOr<RawJwt> jwt =
      RawJwtParser::FromJson(absl::nullopt, R"({"exp":1e30})");
  EXPECT_FALSE(jwt.ok());
}

TEST(RawJwt, FromJsonNegativeExpirationAreInvalid) {
  util::StatusOr<RawJwt> jwt =
      RawJwtParser::FromJson(absl::nullopt, R"({"exp":-1})");
  EXPECT_FALSE(jwt.ok());
}

TEST(RawJwt, FromJsonConvertsStringAudIntoListOfStrings) {
  util::StatusOr<RawJwt> jwt =
      RawJwtParser::FromJson(absl::nullopt, R"({"aud":"audience"})");
  ASSERT_THAT(jwt.status(), IsOk());

  std::vector<std::string> expected = {"audience"};
  EXPECT_TRUE(jwt->HasAudiences());
  EXPECT_THAT(jwt->GetAudiences(), IsOkAndHolds(expected));
}

TEST(RawJwt, FromJsonWithBadRegisteredTypes) {
  EXPECT_FALSE(RawJwtParser::FromJson(absl::nullopt, R"({"iss":123})").ok());
  EXPECT_FALSE(RawJwtParser::FromJson(absl::nullopt, R"({"sub":123})").ok());
  EXPECT_FALSE(RawJwtParser::FromJson(absl::nullopt, R"({"aud":123})").ok());
  EXPECT_FALSE(RawJwtParser::FromJson(absl::nullopt, R"({"aud":[]})").ok());
  EXPECT_FALSE(
      RawJwtParser::FromJson(absl::nullopt, R"({"aud":["abc",123]})").ok());
  EXPECT_FALSE(RawJwtParser::FromJson(absl::nullopt, R"({"exp":"abc"})").ok());
  EXPECT_FALSE(RawJwtParser::FromJson(absl::nullopt, R"({"nbf":"abc"})").ok());
  EXPECT_FALSE(RawJwtParser::FromJson(absl::nullopt, R"({"iat":"abc"})").ok());
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
