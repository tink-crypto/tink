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

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/strings/str_split.h"
#include "tink/cleartext_keyset_handle.h"
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

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

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

// KeysetHandleWithNewKeyId generates a new keyset handle with the exact same
// keyset, except that the key ID of the first key is different.
std::unique_ptr<KeysetHandle> KeysetHandleWithNewKeyId(
    const KeysetHandle& keyset_handle) {
  Keyset keyset(CleartextKeysetHandle::GetKeyset(keyset_handle));
  // Modify the key ID by XORing it with a arbitrary constant value.
  uint32_t new_key_id = keyset.mutable_key(0)->key_id() ^ 0xdeadbeef;
  keyset.mutable_key(0)->set_key_id(new_key_id);
  keyset.set_primary_key_id(new_key_id);
  return CleartextKeysetHandle::GetKeysetHandle(keyset);
}

// KeysetHandleWithTinkPrefix generates a new keyset handle with the exact same
// keyset, except that the output prefix type of the first key is set to TINK.
std::unique_ptr<KeysetHandle> KeysetHandleWithTinkPrefix(
    const KeysetHandle& keyset_handle) {
  Keyset keyset(CleartextKeysetHandle::GetKeyset(keyset_handle));
  keyset.mutable_key(0)->set_output_prefix_type(OutputPrefixType::TINK);
  return CleartextKeysetHandle::GetKeysetHandle(keyset);
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

  util::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(tink_key_template);
  ASSERT_THAT(keyset_handle, IsOk());
  EXPECT_FALSE(
      (*keyset_handle)->GetPrimitive<JwtPublicKeySign>().status().ok());

  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*keyset_handle)->GetPublicKeysetHandle();
  ASSERT_THAT(public_handle, IsOk());
  EXPECT_FALSE(
      (*public_handle)->GetPrimitive<JwtPublicKeyVerify>().status().ok());
}

TEST_F(JwtPublicKeyWrappersTest, GenerateRawSignVerifySuccess) {
  KeyTemplate key_template = CreateTemplate(OutputPrefixType::RAW);
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign =
      (*handle)->GetPrimitive<JwtPublicKeySign>();
  EXPECT_THAT(jwt_sign, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle();
  EXPECT_THAT(public_handle, IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify =
      (*public_handle)->GetPrimitive<JwtPublicKeyVerify>();
  EXPECT_THAT(jwt_verify, IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<std::string> compact = (*jwt_sign)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_verify)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), test::IsOkAndHolds("issuer"));

  util::StatusOr<JwtValidator> validator2 = JwtValidatorBuilder()
                                                .ExpectIssuer("unknown")
                                                .AllowMissingExpiration()
                                                .Build();
  ASSERT_THAT(validator2, IsOk());
  util::StatusOr<VerifiedJwt> verified_jwt2 =
      (*jwt_verify)->VerifyAndDecode(*compact, *validator2);
  EXPECT_FALSE(verified_jwt2.ok());
  // Make sure the error message is interesting
  EXPECT_THAT(verified_jwt2.status().message(), Eq("wrong issuer"));

  // Raw primitives don't add a kid header, Tink primitives require a kid
  // header to be set. Thefore, changing the output prefix to TINK makes the
  // validation fail.
  std::unique_ptr<KeysetHandle> tink_public_handle =
      KeysetHandleWithTinkPrefix(**public_handle);
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> tink_verify =
      tink_public_handle->GetPrimitive<JwtPublicKeyVerify>();
  ASSERT_THAT(tink_verify, IsOk());

  EXPECT_THAT((*tink_verify)->VerifyAndDecode(*compact, *validator).status(),
              Not(IsOk()));
}

TEST_F(JwtPublicKeyWrappersTest, GenerateTinkSignVerifySuccess) {
  KeyTemplate key_template = CreateTemplate(OutputPrefixType::TINK);
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign =
      (*handle)->GetPrimitive<JwtPublicKeySign>();
  EXPECT_THAT(jwt_sign, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle();
  EXPECT_THAT(public_handle, IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify =
      (*public_handle)->GetPrimitive<JwtPublicKeyVerify>();
  EXPECT_THAT(jwt_verify, IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<std::string> compact = (*jwt_sign)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_verify)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), test::IsOkAndHolds("issuer"));

  // Parse header to make sure that key ID is correctly encoded.
  google::crypto::tink::KeysetInfo keyset_info =
      (*public_handle)->GetKeysetInfo();
  uint32_t key_id = keyset_info.key_info(0).key_id();
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts, SizeIs(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header, IsOk());
  google::protobuf::Value value = (*header).fields().find("kid")->second;
  EXPECT_THAT(GetKeyId(value.string_value()), Eq(key_id));

  // For Tink primitives, the kid must be correctly set and verified.
  // Therefore, changing the key_id makes the validation fail.
  std::unique_ptr<KeysetHandle> public_handle_with_new_key_id =
      KeysetHandleWithNewKeyId(**public_handle);
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify_with_new_key_id =
      public_handle_with_new_key_id->GetPrimitive<JwtPublicKeyVerify>();
  ASSERT_THAT(verify_with_new_key_id, IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt_2 =
      (*verify_with_new_key_id)->VerifyAndDecode(*compact, *validator);
  EXPECT_FALSE(verified_jwt_2.ok());
}

TEST_F(JwtPublicKeyWrappersTest, KeyRotation) {
  std::vector<OutputPrefixType> prefixes = {OutputPrefixType::RAW,
                                            OutputPrefixType::TINK};
  for (OutputPrefixType prefix : prefixes) {
    SCOPED_TRACE(absl::StrCat("Testing with prefix ", prefix));
    KeyTemplate key_template = CreateTemplate(prefix);
    KeysetManager manager;

    util::StatusOr<uint32_t> old_id = manager.Add(key_template);
    ASSERT_THAT(old_id, IsOk());
    ASSERT_THAT(manager.SetPrimary(*old_id), IsOk());
    std::unique_ptr<KeysetHandle> handle1 = manager.GetKeysetHandle();
    util::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign1 =
        handle1->GetPrimitive<JwtPublicKeySign>();
    ASSERT_THAT(jwt_sign1, IsOk());
    util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle1 =
        handle1->GetPublicKeysetHandle();
    EXPECT_THAT(public_handle1, IsOk());
    util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify1 =
        (*public_handle1)->GetPrimitive<JwtPublicKeyVerify>();
    EXPECT_THAT(jwt_verify1, IsOk());

    util::StatusOr<uint32_t> new_id = manager.Add(key_template);
    ASSERT_THAT(new_id, IsOk());
    std::unique_ptr<KeysetHandle> handle2 = manager.GetKeysetHandle();
    util::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign2 =
        handle2->GetPrimitive<JwtPublicKeySign>();
    ASSERT_THAT(jwt_sign2, IsOk());
    util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle2 =
        handle2->GetPublicKeysetHandle();
    EXPECT_THAT(public_handle2, IsOk());
    util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify2 =
        (*public_handle2)->GetPrimitive<JwtPublicKeyVerify>();
    EXPECT_THAT(jwt_verify2, IsOk());

    ASSERT_THAT(manager.SetPrimary(*new_id), IsOk());
    std::unique_ptr<KeysetHandle> handle3 = manager.GetKeysetHandle();
    util::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign3 =
        handle3->GetPrimitive<JwtPublicKeySign>();
    ASSERT_THAT(jwt_sign3, IsOk());
    util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle3 =
        handle3->GetPublicKeysetHandle();
    EXPECT_THAT(public_handle3, IsOk());
    util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify3 =
        (*public_handle3)->GetPrimitive<JwtPublicKeyVerify>();
    EXPECT_THAT(jwt_verify3, IsOk());

    ASSERT_THAT(manager.Disable(*old_id), IsOk());
    std::unique_ptr<KeysetHandle> handle4 = manager.GetKeysetHandle();
    util::StatusOr<std::unique_ptr<JwtPublicKeySign>> jwt_sign4 =
        handle4->GetPrimitive<JwtPublicKeySign>();
    ASSERT_THAT(jwt_sign4, IsOk());
    util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle4 =
        handle4->GetPublicKeysetHandle();
    EXPECT_THAT(public_handle4, IsOk());
    util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> jwt_verify4 =
        (*public_handle4)->GetPrimitive<JwtPublicKeyVerify>();
    EXPECT_THAT(jwt_verify4, IsOk());

    util::StatusOr<RawJwt> raw_jwt =
        RawJwtBuilder().SetJwtId("id123").WithoutExpiration().Build();
    ASSERT_THAT(raw_jwt, IsOk());
    util::StatusOr<JwtValidator> validator =
        JwtValidatorBuilder().AllowMissingExpiration().Build();
    ASSERT_THAT(raw_jwt, IsOk());

    util::StatusOr<std::string> compact1 =
        (*jwt_sign1)->SignAndEncode(*raw_jwt);
    ASSERT_THAT(compact1, IsOk());

    util::StatusOr<std::string> compact2 =
        (*jwt_sign2)->SignAndEncode(*raw_jwt);
    ASSERT_THAT(compact2, IsOk());

    util::StatusOr<std::string> compact3 =
        (*jwt_sign3)->SignAndEncode(*raw_jwt);
    ASSERT_THAT(compact3, IsOk());

    util::StatusOr<std::string> compact4 =
        (*jwt_sign4)->SignAndEncode(*raw_jwt);
    ASSERT_THAT(compact4, IsOk());

    EXPECT_THAT((*jwt_verify1)->VerifyAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_verify2)->VerifyAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_verify3)->VerifyAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_FALSE((*jwt_verify4)->VerifyAndDecode(*compact1, *validator).ok());

    EXPECT_THAT((*jwt_verify1)->VerifyAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_verify2)->VerifyAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_verify3)->VerifyAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_FALSE((*jwt_verify4)->VerifyAndDecode(*compact2, *validator).ok());

    EXPECT_FALSE((*jwt_verify1)->VerifyAndDecode(*compact3, *validator).ok());
    EXPECT_THAT((*jwt_verify2)->VerifyAndDecode(*compact3, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_verify3)->VerifyAndDecode(*compact3, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_verify4)->VerifyAndDecode(*compact3, *validator).status(),
                IsOk());

    EXPECT_FALSE((*jwt_verify1)->VerifyAndDecode(*compact4, *validator).ok());
    EXPECT_THAT((*jwt_verify2)->VerifyAndDecode(*compact4, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_verify3)->VerifyAndDecode(*compact4, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_verify4)->VerifyAndDecode(*compact4, *validator).status(),
                IsOk());
  }
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
