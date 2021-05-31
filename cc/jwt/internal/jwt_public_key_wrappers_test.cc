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

#include "gtest/gtest.h"
#include "absl/strings/str_split.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_public_key_sign_wrapper.h"
#include "tink/jwt/internal/jwt_public_key_verify_wrapper.h"
#include "tink/keyset_manager.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;

KeyTemplate CreateTemplate(OutputPrefixType output_prefix) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey");
  key_template.set_output_prefix_type(output_prefix);
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

class JwtPublicKeyWrappersTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
        absl::make_unique<JwtPublicKeySignWrapper>()), IsOk());
    ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
        absl::make_unique<JwtPublicKeyVerifyWrapper>()), IsOk());
    ASSERT_THAT(Registry::RegisterAsymmetricKeyManagers(
                    absl::make_unique<JwtEcdsaSignKeyManager>(),
                    absl::make_unique<JwtEcdsaVerifyKeyManager>(), true),
                IsOk());
  }
};

TEST_F(JwtPublicKeyWrappersTest, WrapNullptrSign) {
  EXPECT_FALSE(JwtPublicKeySignWrapper().Wrap(nullptr).ok());
}

TEST_F(JwtPublicKeyWrappersTest, WrapNullptrVerify) {
  EXPECT_FALSE(JwtPublicKeyVerifyWrapper().Wrap(nullptr).ok());
}

TEST_F(JwtPublicKeyWrappersTest, WrapEmptySign) {
  auto jwt_sign_set =
      absl::make_unique<PrimitiveSet<JwtPublicKeySignInternal>>();
  auto result = JwtPublicKeySignWrapper().Wrap(std::move(jwt_sign_set));
  EXPECT_FALSE(result.ok());
}

TEST_F(JwtPublicKeyWrappersTest, CannotWrapPrimitivesFromNonRawOrTinkKeys) {
  KeyTemplate tink_key_template = CreateTemplate(OutputPrefixType::LEGACY);

  auto handle_or = KeysetHandle::GenerateNew(tink_key_template);
  ASSERT_THAT(handle_or.status(), IsOk());
  auto keyset_handle = std::move(handle_or.ValueOrDie());
  EXPECT_FALSE(keyset_handle->GetPrimitive<JwtPublicKeySign>().status().ok());

  auto public_handle_or = keyset_handle->GetPublicKeysetHandle();
  ASSERT_THAT(public_handle_or.status(), IsOk());
  auto public_handle = std::move(public_handle_or.ValueOrDie());
  EXPECT_FALSE(
      public_handle->GetPrimitive<JwtPublicKeyVerify>().status().ok());
}

TEST_F(JwtPublicKeyWrappersTest, GenerateRawSignVerifySuccess) {
  KeyTemplate key_template = CreateTemplate(OutputPrefixType::RAW);
  auto handle_or = KeysetHandle::GenerateNew(key_template);
  ASSERT_THAT(handle_or.status(), IsOk());
  auto jwt_sign_or = handle_or.ValueOrDie()->GetPrimitive<JwtPublicKeySign>();
  EXPECT_THAT(jwt_sign_or.status(), IsOk());
  std::unique_ptr<JwtPublicKeySign> jwt_sign =
      std::move(jwt_sign_or.ValueOrDie());

  auto public_handle_or = handle_or.ValueOrDie()->GetPublicKeysetHandle();
  EXPECT_THAT(public_handle_or.status(), IsOk());
  auto jwt_verify_or =
      public_handle_or.ValueOrDie()->GetPrimitive<JwtPublicKeyVerify>();
  EXPECT_THAT(jwt_verify_or.status(), IsOk());
  std::unique_ptr<JwtPublicKeyVerify> jwt_verify =
      std::move(jwt_verify_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  RawJwt raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or = jwt_sign->SignAndEncode(raw_jwt);
  ASSERT_THAT(compact_or.status(), IsOk());
  std::string compact = compact_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();
  util::StatusOr<VerifiedJwt> verified_jwt_or =
      jwt_verify->VerifyAndDecode(compact, validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  auto verified_jwt = verified_jwt_or.ValueOrDie();
  EXPECT_THAT(verified_jwt.GetIssuer(), test::IsOkAndHolds("issuer"));

  JwtValidator validator2 =
      JwtValidatorBuilder().ExpectIssuer("unknown").Build();
  EXPECT_FALSE(jwt_verify->VerifyAndDecode(compact, validator2).ok());
}

TEST_F(JwtPublicKeyWrappersTest, GenerateTinkSignVerifySuccess) {
  KeyTemplate key_template = CreateTemplate(OutputPrefixType::TINK);
  auto handle_or = KeysetHandle::GenerateNew(key_template);
  ASSERT_THAT(handle_or.status(), IsOk());
  auto jwt_sign_or = handle_or.ValueOrDie()->GetPrimitive<JwtPublicKeySign>();
  EXPECT_THAT(jwt_sign_or.status(), IsOk());
  std::unique_ptr<JwtPublicKeySign> jwt_sign =
      std::move(jwt_sign_or.ValueOrDie());

  auto public_handle_or = handle_or.ValueOrDie()->GetPublicKeysetHandle();
  EXPECT_THAT(public_handle_or.status(), IsOk());
  auto jwt_verify_or =
      public_handle_or.ValueOrDie()->GetPrimitive<JwtPublicKeyVerify>();
  EXPECT_THAT(jwt_verify_or.status(), IsOk());
  std::unique_ptr<JwtPublicKeyVerify> jwt_verify =
      std::move(jwt_verify_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  RawJwt raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or = jwt_sign->SignAndEncode(raw_jwt);
  ASSERT_THAT(compact_or.status(), IsOk());
  std::string compact = compact_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();
  util::StatusOr<VerifiedJwt> verified_jwt_or =
      jwt_verify->VerifyAndDecode(compact, validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  auto verified_jwt = verified_jwt_or.ValueOrDie();
  EXPECT_THAT(verified_jwt.GetIssuer(), test::IsOkAndHolds("issuer"));

  // parse header to make sure that key ID is correctly encoded.
  auto keyset_info = public_handle_or.ValueOrDie()->GetKeysetInfo();
  uint32_t key_id = keyset_info.key_info(0).key_id();
  std::vector<absl::string_view> parts =
      absl::StrSplit(compact_or.ValueOrDie(), '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  auto header_or = JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header_or.status(), IsOk());
  EXPECT_THAT(
      GetKeyId(
          header_or.ValueOrDie().fields().find("kid")->second.string_value()),
      key_id);
}

TEST_F(JwtPublicKeyWrappersTest, KeyRotation) {
  std::vector<OutputPrefixType> prefixes = {OutputPrefixType::RAW,
                                            OutputPrefixType::TINK};
  for (OutputPrefixType prefix : prefixes) {
    SCOPED_TRACE(absl::StrCat("Testing with prefix ", prefix));
    KeyTemplate key_template = CreateTemplate(prefix);
    KeysetManager manager;

    auto old_id_or = manager.Add(key_template);
    ASSERT_THAT(old_id_or.status(), IsOk());
    uint32_t old_id = old_id_or.ValueOrDie();
    ASSERT_THAT(manager.SetPrimary(old_id), IsOk());
    std::unique_ptr<KeysetHandle> handle1 = manager.GetKeysetHandle();
    auto jwt_sign1_or = handle1->GetPrimitive<JwtPublicKeySign>();
    ASSERT_THAT(jwt_sign1_or.status(), IsOk());
    std::unique_ptr<JwtPublicKeySign> jwt_sign1 =
        std::move(jwt_sign1_or.ValueOrDie());
    auto public_handle1_or = handle1->GetPublicKeysetHandle();
    EXPECT_THAT(public_handle1_or.status(), IsOk());
    auto jwt_verify1_or =
        public_handle1_or.ValueOrDie()->GetPrimitive<JwtPublicKeyVerify>();
    EXPECT_THAT(jwt_verify1_or.status(), IsOk());
    std::unique_ptr<JwtPublicKeyVerify> jwt_verify1 =
        std::move(jwt_verify1_or.ValueOrDie());

    auto new_id_or = manager.Add(key_template);
    ASSERT_THAT(new_id_or.status(), IsOk());
    uint32_t new_id = new_id_or.ValueOrDie();
    std::unique_ptr<KeysetHandle> handle2 = manager.GetKeysetHandle();
    auto jwt_sign2_or = handle2->GetPrimitive<JwtPublicKeySign>();
    ASSERT_THAT(jwt_sign2_or.status(), IsOk());
    std::unique_ptr<JwtPublicKeySign> jwt_sign2 =
        std::move(jwt_sign2_or.ValueOrDie());
    auto public_handle2_or = handle2->GetPublicKeysetHandle();
    EXPECT_THAT(public_handle2_or.status(), IsOk());
    auto jwt_verify2_or =
        public_handle2_or.ValueOrDie()->GetPrimitive<JwtPublicKeyVerify>();
    EXPECT_THAT(jwt_verify2_or.status(), IsOk());
    std::unique_ptr<JwtPublicKeyVerify> jwt_verify2 =
        std::move(jwt_verify2_or.ValueOrDie());

    ASSERT_THAT(manager.SetPrimary(new_id), IsOk());
    std::unique_ptr<KeysetHandle> handle3 = manager.GetKeysetHandle();
    auto jwt_sign3_or = handle3->GetPrimitive<JwtPublicKeySign>();
    ASSERT_THAT(jwt_sign3_or.status(), IsOk());
    std::unique_ptr<JwtPublicKeySign> jwt_sign3 =
        std::move(jwt_sign3_or.ValueOrDie());
    auto public_handle3_or = handle3->GetPublicKeysetHandle();
    EXPECT_THAT(public_handle3_or.status(), IsOk());
    auto jwt_verify3_or =
        public_handle3_or.ValueOrDie()->GetPrimitive<JwtPublicKeyVerify>();
    EXPECT_THAT(jwt_verify3_or.status(), IsOk());
    std::unique_ptr<JwtPublicKeyVerify> jwt_verify3 =
        std::move(jwt_verify3_or.ValueOrDie());

    ASSERT_THAT(manager.Disable(old_id), IsOk());
    std::unique_ptr<KeysetHandle> handle4 = manager.GetKeysetHandle();
    auto jwt_sign4_or = handle4->GetPrimitive<JwtPublicKeySign>();
    ASSERT_THAT(jwt_sign4_or.status(), IsOk());
    std::unique_ptr<JwtPublicKeySign> jwt_sign4 =
        std::move(jwt_sign4_or.ValueOrDie());
    auto public_handle4_or = handle4->GetPublicKeysetHandle();
    EXPECT_THAT(public_handle4_or.status(), IsOk());
    auto jwt_verify4_or =
        public_handle4_or.ValueOrDie()->GetPrimitive<JwtPublicKeyVerify>();
    EXPECT_THAT(jwt_verify4_or.status(), IsOk());
    std::unique_ptr<JwtPublicKeyVerify> jwt_verify4 =
        std::move(jwt_verify4_or.ValueOrDie());

    auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
    ASSERT_THAT(raw_jwt_or.status(), IsOk());
    RawJwt raw_jwt = raw_jwt_or.ValueOrDie();
    JwtValidator validator = JwtValidatorBuilder().Build();

    util::StatusOr<std::string> compact1_or = jwt_sign1->SignAndEncode(raw_jwt);
    ASSERT_THAT(compact1_or.status(), IsOk());
    std::string compact1 = compact1_or.ValueOrDie();

    util::StatusOr<std::string> compact2_or = jwt_sign2->SignAndEncode(raw_jwt);
    ASSERT_THAT(compact2_or.status(), IsOk());
    std::string compact2 = compact2_or.ValueOrDie();

    util::StatusOr<std::string> compact3_or = jwt_sign3->SignAndEncode(raw_jwt);
    ASSERT_THAT(compact3_or.status(), IsOk());
    std::string compact3 = compact3_or.ValueOrDie();

    util::StatusOr<std::string> compact4_or = jwt_sign4->SignAndEncode(raw_jwt);
    ASSERT_THAT(compact4_or.status(), IsOk());
    std::string compact4 = compact4_or.ValueOrDie();

    EXPECT_THAT(jwt_verify1->VerifyAndDecode(compact1, validator).status(),
                IsOk());
    EXPECT_THAT(jwt_verify2->VerifyAndDecode(compact1, validator).status(),
                IsOk());
    EXPECT_THAT(jwt_verify3->VerifyAndDecode(compact1, validator).status(),
                IsOk());
    EXPECT_FALSE(jwt_verify4->VerifyAndDecode(compact1, validator).ok());

    EXPECT_THAT(jwt_verify1->VerifyAndDecode(compact2, validator).status(),
                IsOk());
    EXPECT_THAT(jwt_verify2->VerifyAndDecode(compact2, validator).status(),
                IsOk());
    EXPECT_THAT(jwt_verify3->VerifyAndDecode(compact2, validator).status(),
                IsOk());
    EXPECT_FALSE(jwt_verify4->VerifyAndDecode(compact2, validator).ok());

    EXPECT_FALSE(jwt_verify1->VerifyAndDecode(compact3, validator).ok());
    EXPECT_THAT(jwt_verify2->VerifyAndDecode(compact3, validator).status(),
                IsOk());
    EXPECT_THAT(jwt_verify3->VerifyAndDecode(compact3, validator).status(),
                IsOk());
    EXPECT_THAT(jwt_verify4->VerifyAndDecode(compact3, validator).status(),
                IsOk());

    EXPECT_FALSE(jwt_verify1->VerifyAndDecode(compact4, validator).ok());
    EXPECT_THAT(jwt_verify2->VerifyAndDecode(compact4, validator).status(),
                IsOk());
    EXPECT_THAT(jwt_verify3->VerifyAndDecode(compact4, validator).status(),
                IsOk());
    EXPECT_THAT(jwt_verify4->VerifyAndDecode(compact4, validator).status(),
                IsOk());
  }
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
