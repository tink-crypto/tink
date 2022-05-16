// Copyright 2021 Google LLC
//
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

#include "tink/jwt/internal/jwt_hmac_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "absl/time/time.h"
#include "tink/core/key_manager_impl.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/mac.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::JwtHmacAlgorithm;
using ::google::crypto::tink::JwtHmacKey;
using ::google::crypto::tink::JwtHmacKeyFormat;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(JwtHmacKeyManagerTest, Basics) {
  EXPECT_EQ(JwtHmacKeyManager().get_version(), 0);
  EXPECT_EQ(JwtHmacKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.JwtHmacKey");
  EXPECT_EQ(JwtHmacKeyManager().key_material_type(),
            google::crypto::tink::KeyData::SYMMETRIC);
}

TEST(JwtHmacKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(JwtHmacKey()), Not(IsOk()));
}

TEST(JwtHmacKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(JwtHmacKeyFormat()),
              Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, ValidateHS256KeyFormat) {
  JwtHmacKeyFormat key_format;
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  key_format.set_key_size(32);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.set_key_size(31);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, ValidateHS384KeyFormat) {
  JwtHmacKeyFormat key_format;
  key_format.set_algorithm(JwtHmacAlgorithm::HS384);
  key_format.set_key_size(48);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.set_key_size(47);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, ValidateHS512KeyFormat) {
  JwtHmacKeyFormat key_format;
  key_format.set_algorithm(JwtHmacAlgorithm::HS512);
  key_format.set_key_size(64);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.set_key_size(63);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(JwtHmacKeyManagerTest, CreateKey) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  util::StatusOr<google::crypto::tink::JwtHmacKey> key =
      JwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_EQ(key->version(), 0);
  EXPECT_EQ(key->algorithm(), key_format.algorithm());
  EXPECT_THAT(key->key_value(), SizeIs(key_format.key_size()));

  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(*key), IsOk());
}

TEST(JwtHmacKeyManagerTest, ValidateKeyWithUnknownAlgorithm_fails) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_algorithm(JwtHmacAlgorithm::HS_UNKNOWN);
  key.set_key_value("0123456789abcdef0123456789abcdef");

  EXPECT_FALSE(JwtHmacKeyManager().ValidateKey(key).ok());
}

TEST(JwtHmacKeyManagerTest, ValidateHS256Key) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_algorithm(JwtHmacAlgorithm::HS256);
  key.set_key_value("0123456789abcdef0123456789abcdef");  // 32 bytes
  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), IsOk());
  key.set_key_value("0123456789abcdef0123456789abcde");  // 31 bytes
  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(JwtHmacKeyManagerTest, ValidateHS384Key) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_algorithm(JwtHmacAlgorithm::HS384);
  key.set_key_value(
      "0123456789abcdef0123456789abcdef0123456789abcdef");  // 48 bytes
  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), IsOk());
  key.set_key_value(
      "0123456789abcdef0123456789abcdef0123456789abcde");  // 47 bytes
  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(JwtHmacKeyManagerTest, ValidateHS512Key) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_algorithm(JwtHmacAlgorithm::HS512);
  key.set_key_value(  // 64 bytes
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  key.set_key_value(  // 63 bytes
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde");
  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), Not(IsOk()));
}


TEST(JwtHmacKeyManagerTest, DeriveKeyIsNotImplemented) {
  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);
  format.set_algorithm(JwtHmacAlgorithm::HS256);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};

  ASSERT_THAT(JwtHmacKeyManager().DeriveKey(format, &input_stream).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(JwtHmacKeyManagerTest, GetAndUsePrimitive) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  util::StatusOr<google::crypto::tink::JwtHmacKey> key =
      JwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac =
      JwtHmacKeyManager().GetPrimitive<JwtMacInternal>(*key);
  ASSERT_THAT(jwt_mac.status(), IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact.status(), IsOk());
  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(*compact, *validator,
                                            /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt.status(), IsOk());
  util::StatusOr<std::string> issuer = verified_jwt->GetIssuer();
  EXPECT_THAT(issuer, IsOkAndHolds("issuer"));
}

TEST(JwtHmacKeyManagerTest, GetAndUsePrimitiveWithKid) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  util::StatusOr<google::crypto::tink::JwtHmacKey> key =
      JwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac =
      JwtHmacKeyManager().GetPrimitive<JwtMacInternal>(*key);
  ASSERT_THAT(jwt_mac.status(), IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());

  util::StatusOr<std::string> token_with_kid =
      (*jwt_mac)->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/"kid-123");
  ASSERT_THAT(token_with_kid.status(), IsOk());
  util::StatusOr<std::string> token_without_kid =
      (*jwt_mac)->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(token_without_kid.status(), IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());

  // A token with kid only fails if the wrong kid is passed.
  ASSERT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(*token_with_kid, *validator,
                                              /*kid=*/absl::nullopt)
                  .status(),
              IsOk());
  ASSERT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(*token_with_kid, *validator,
                                              /*kid=*/"kid-123")
                  .status(),
              IsOk());
  ASSERT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(*token_with_kid, *validator,
                                              /*kid=*/"wrong-kid")
                  .status(),
              Not(IsOk()));

  // A token without kid is only valid if no kid is passed.
  ASSERT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(*token_without_kid, *validator,
                                              /*kid=*/absl::nullopt)
                  .status(),
              IsOk());
  ASSERT_THAT(
      (*jwt_mac)
          ->VerifyMacAndDecodeWithKid(*token_without_kid, *validator, "kid-123")
          .status(),
      Not(IsOk()));
}

TEST(JwtHmacKeyManagerTest, GetAndUsePrimitiveWithCustomKid) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  util::StatusOr<JwtHmacKey> key = JwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());
  key->mutable_custom_kid()->set_value(
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit");

  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac =
      JwtHmacKeyManager().GetPrimitive<JwtMacInternal>(*key);
  ASSERT_THAT(jwt_mac.status(), IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt.status(), IsOk());

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/absl::nullopt);
  ASSERT_THAT(compact.status(), IsOk());
  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator.status(), IsOk());
  // parse header and check "kid"
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header.status(), IsOk());
  auto it = header->fields().find("kid");
  ASSERT_FALSE(it == header->fields().end());
  EXPECT_THAT(it->second.string_value(),
              Eq("Lorem ipsum dolor sit amet, consectetur adipiscing elit"));

  // validate token
  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(*compact, *validator,
                                            /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt.status(), IsOk());
  util::StatusOr<std::string> issuer = verified_jwt->GetIssuer();
  ASSERT_THAT(issuer.status(), IsOk());
  EXPECT_THAT(*issuer, testing::Eq("issuer"));

  // passing a kid when custom_kid is set should fail
  EXPECT_THAT((*jwt_mac)
                  ->ComputeMacAndEncodeWithKid(*raw_jwt, /*kid=*/"kid123")
                  .status(),
              Not(IsOk()));
}

TEST(JwtHmacKeyManagerTest, ValidateTokenWithFixedKey) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_algorithm(JwtHmacAlgorithm::HS256);

  std::string key_value;
  ASSERT_TRUE(absl::WebSafeBase64Unescape(
      "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1"
      "qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
      &key_value));
  key.set_key_value(key_value);
  util::StatusOr<std::unique_ptr<JwtMacInternal>> jwt_mac =
      JwtHmacKeyManager().GetPrimitive<JwtMacInternal>(key);
  ASSERT_THAT(jwt_mac.status(), IsOk());

  std::string compact =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH"
      "AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder()
          .ExpectTypeHeader("JWT")
          .ExpectIssuer("joe")
          .SetFixedNow(absl::FromUnixSeconds(12345))
          .Build();
  ASSERT_THAT(validator.status(), IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecodeWithKid(compact, *validator,
                                            /*kid=*/absl::nullopt);
  ASSERT_THAT(verified_jwt.status(), IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("joe"));
  EXPECT_THAT(verified_jwt->GetBooleanClaim("http://example.com/is_root"),
              IsOkAndHolds(true));

  util::StatusOr<JwtValidator> validator_now = JwtValidatorBuilder().Build();
  ASSERT_THAT(validator_now.status(), IsOk());
  EXPECT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(compact, *validator_now,
                                              /*kid=*/absl::nullopt)
                  .status(),
              Not(IsOk()));

  std::string modified_compact =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH"
      "AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXi";
  EXPECT_THAT((*jwt_mac)
                  ->VerifyMacAndDecodeWithKid(modified_compact, *validator,
                                              /*kid=*/absl::nullopt)
                  .status(),
              Not(IsOk()));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
