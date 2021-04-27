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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
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

  std::string output;
  ASSERT_TRUE(DecodeHeader(encoded_header, &output));
  EXPECT_THAT(output, Eq("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"));

  EXPECT_THAT(ValidateHeader(encoded_header, "HS256"), IsOk());
  EXPECT_FALSE(ValidateHeader(encoded_header, "RS256").ok());
}

TEST(JwtFormat, DecodeAndValidateFixedHeaderRS256) {
  // Example from https://tools.ietf.org/html/rfc7515#appendix-A.2
  std::string encoded_header = "eyJhbGciOiJSUzI1NiJ9";

  std::string output;
  ASSERT_TRUE(DecodeHeader(encoded_header, &output));
  EXPECT_THAT(output, Eq(R"({"alg":"RS256"})"));

  EXPECT_THAT(ValidateHeader(encoded_header, "RS256"), IsOk());
  EXPECT_FALSE(ValidateHeader(encoded_header, "HS256").ok());
}

TEST(JwtFormat, CreateValidateHeader) {
  std::string encoded_header = CreateHeader("PS384");
  EXPECT_THAT(ValidateHeader(encoded_header, "PS384"), IsOk());
  EXPECT_FALSE(ValidateHeader(encoded_header, "HS256").ok());
}

TEST(JwtFormat, ValidateEmptyHeaderFails) {
  std::string header = "{}";
  EXPECT_FALSE(ValidateHeader(EncodeHeader(header), "HS256").ok());
}

TEST(JwtFormat, ValidateInvalidEncodedHeaderFails) {
  EXPECT_FALSE(
      ValidateHeader("eyJ0eXAiOiJKV1Q?LA0KICJhbGciOiJIUzI1NiJ9", "HS256").ok());
}

TEST(JwtFormat, ValidateInvalidJsonHeaderFails) {
  std::string header = R"({"alg":"HS256")";  // missing }
  EXPECT_FALSE(ValidateHeader(EncodeHeader(header), "HS256").ok());
}

TEST(JwtFormat, ValidateHeaderIgnoresTyp) {
  std::string header = R"({"alg":"HS256","typ":"unknown"})";
  EXPECT_THAT(ValidateHeader(EncodeHeader(header), "HS256"), IsOk());
}

TEST(JwtFormat, ValidateHeaderRejectsCrit) {
  std::string header =
      R"({"alg":"HS256","crit":["http://example.invalid/UNDEFINED"],)"
      R"("http://example.invalid/UNDEFINED":true})";
  EXPECT_FALSE(ValidateHeader(EncodeHeader(header), "HS256").ok());
}

TEST(JwtFormat, ValidateHeaderWithUnknownEntry) {
  std::string header = R"({"alg":"HS256","unknown":"header"})";
  EXPECT_THAT(ValidateHeader(EncodeHeader(header), "HS256"), IsOk());
}

TEST(JwtFormat, ValidateHeaderWithInvalidAlgTypFails) {
  std::string header = R"({"alg":true})";
  EXPECT_FALSE(ValidateHeader(EncodeHeader(header), "HS256").ok());
}

TEST(JwtFormat, DecodeFixedPayload) {
  // Example from https://tools.ietf.org/html/rfc7519#section-3.1
  std::string encoded_header =
      "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0"
      "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

  std::string expected =
      "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n "
      "\"http://example.com/is_root\":true}";
  std::string output;
  ASSERT_TRUE(DecodePayload(encoded_header, &output));
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

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
