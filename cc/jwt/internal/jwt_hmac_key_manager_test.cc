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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/time/time.h"
#include "tink/core/key_manager_impl.h"
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
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::JwtHmacKey;
using ::google::crypto::tink::JwtHmacKeyFormat;
using ::google::crypto::tink::KeyData;
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

TEST(JwtHmacKeyManagerTest, ValidKeyFormatHS256) {
  JwtHmacKeyFormat key_format;
  key_format.set_hash_type(HashType::SHA256);
  key_format.set_key_size(32);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(JwtHmacKeyManagerTest, ValidateKeyFormatHS384) {
  JwtHmacKeyFormat key_format;
  key_format.set_hash_type(HashType::SHA384);
  key_format.set_key_size(32);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(JwtHmacKeyManagerTest, ValidateKeyFormatHS512) {
  JwtHmacKeyFormat key_format;
  key_format.set_hash_type(HashType::SHA512);
  key_format.set_key_size(32);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(JwtHmacKeyManagerTest, KeyTooShort) {
  JwtHmacKeyFormat key_format;
  key_format.set_hash_type(HashType::SHA256);

  key_format.set_key_size(31);
  EXPECT_THAT(JwtHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(JwtHmacKeyManagerTest, CreateKey) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_hash_type(HashType::SHA512);
  auto key_or = JwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_EQ(key_or.ValueOrDie().version(), 0);
  EXPECT_EQ(key_or.ValueOrDie().hash_type(), key_format.hash_type());
  EXPECT_THAT(key_or.ValueOrDie().key_value(), SizeIs(key_format.key_size()));

  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key_or.ValueOrDie()), IsOk());
}

TEST(JwtHmacKeyManagerTest, ValidateKeySha1_fails) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_hash_type(HashType::SHA1);
  key.set_key_value("0123456789abcdef0123456789abcdef");

  EXPECT_FALSE(JwtHmacKeyManager().ValidateKey(key).ok());
}

TEST(JwtHmacKeyManagerTest, ValidateKeySha224_fails) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_hash_type(HashType::SHA224);
  key.set_key_value("0123456789abcdef0123456789abcdef");

  EXPECT_FALSE(JwtHmacKeyManager().ValidateKey(key).ok());
}

TEST(JwtHmacKeyManagerTest, ValidateKeySha256) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_hash_type(HashType::SHA256);
  key.set_key_value("0123456789abcdef0123456789abcdef");

  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), IsOk());
}

TEST(JwtHmacKeyManagerTest, ValidateKeySha384) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_hash_type(HashType::SHA384);
  key.set_key_value("0123456789abcdef0123456789abcdef");

  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), IsOk());
}

TEST(JwtHmacKeyManagerTest, ValidateKeySha512) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_hash_type(HashType::SHA512);
  key.set_key_value("0123456789abcdef0123456789abcdef");

  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), IsOk());
}

TEST(JwtHmacKeyManagerTest, ValidateKeyTooShort) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_hash_type(HashType::SHA256);
  key.set_key_value("0123456789abcdef0123456789abcde");

  EXPECT_THAT(JwtHmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(JwtHmacKeyManagerTest, DeriveKeyIsNotImplemented) {
  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);
  format.set_hash_type(HashType::SHA256);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};

  ASSERT_THAT(JwtHmacKeyManager().DeriveKey(format, &input_stream).status(),
              StatusIs(util::error::UNIMPLEMENTED));
}

TEST(JwtHmacKeyManagerTest, GetPrimitive) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_hash_type(HashType::SHA512);
  auto key_or = JwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());

  auto jwt_mac_or =
      JwtHmacKeyManager().GetPrimitive<JwtMac>(key_or.ValueOrDie());
  ASSERT_THAT(jwt_mac_or.status(), IsOk());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  auto raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or =
      jwt_mac_or.ValueOrDie()->ComputeMacAndEncode(raw_jwt);
  ASSERT_THAT(compact_or.status(), IsOk());
  JwtValidator validator = JwtValidatorBuilder().SetIssuer("issuer").Build();

  util::StatusOr<VerifiedJwt> verified_jwt_or =
      jwt_mac_or.ValueOrDie()->VerifyMacAndDecode(compact_or.ValueOrDie(),
                                                  validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  util::StatusOr<std::string> issuer_or =
      verified_jwt_or.ValueOrDie().GetIssuer();
  ASSERT_THAT(issuer_or.status(), IsOk());
  EXPECT_THAT(issuer_or.ValueOrDie(), testing::Eq("issuer"));
}

TEST(JwtHmacKeyManagerTest, ValidateTokenWithFixedKey) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_hash_type(HashType::SHA256);

  std::string key_value;
  ASSERT_TRUE(absl::WebSafeBase64Unescape(
      "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1"
      "qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
      &key_value));
  key.set_key_value(key_value);
  auto jwt_mac_or = JwtHmacKeyManager().GetPrimitive<JwtMac>(key);
  ASSERT_THAT(jwt_mac_or.status(), IsOk());

  std::string compact =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH"
      "AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  JwtValidator validator =
      JwtValidatorBuilder().SetFixedNow(absl::FromUnixSeconds(12345)).Build();

  util::StatusOr<VerifiedJwt> verified_jwt_or =
      jwt_mac_or.ValueOrDie()->VerifyMacAndDecode(compact, validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  auto verified_jwt = verified_jwt_or.ValueOrDie();
  EXPECT_THAT(verified_jwt.GetIssuer(), test::IsOkAndHolds("joe"));
  EXPECT_THAT(verified_jwt.GetBooleanClaim("http://example.com/is_root"),
              test::IsOkAndHolds(true));

  JwtValidator validator_now = JwtValidatorBuilder().Build();
  EXPECT_FALSE(
      jwt_mac_or.ValueOrDie()->VerifyMacAndDecode(compact, validator_now).ok());

  std::string modified_compact =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH"
      "AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXi";
  EXPECT_FALSE(jwt_mac_or.ValueOrDie()
                   ->VerifyMacAndDecode(modified_compact, validator)
                   .ok());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
