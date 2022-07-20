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

#include "tink/jwt/internal/jwt_mac_wrapper.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/strings/str_split.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/jwt/internal/json_util.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_hmac_key_manager.h"
#include "tink/keyset_manager.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::JwtHmacAlgorithm;
using google::crypto::tink::JwtHmacKeyFormat;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::Keyset;
using ::testing::Eq;
using ::testing::Not;

KeyTemplate createTemplate(OutputPrefixType output_prefix) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtHmacKey");
  key_template.set_output_prefix_type(output_prefix);
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

std::unique_ptr<KeysetHandle> KeysetHandleWithNewKeyId(
    const KeysetHandle& keyset_handle) {
  Keyset keyset(CleartextKeysetHandle::GetKeyset(keyset_handle));
  uint32_t new_key_id = keyset.mutable_key(0)->key_id() ^ 0xdeadbeef;
  keyset.mutable_key(0)->set_key_id(new_key_id);
  keyset.set_primary_key_id(new_key_id);
  return CleartextKeysetHandle::GetKeysetHandle(keyset);
}

std::unique_ptr<KeysetHandle> KeysetHandleWithTinkPrefix(
    const KeysetHandle& keyset_handle) {
  Keyset keyset(CleartextKeysetHandle::GetKeyset(keyset_handle));
  keyset.mutable_key(0)->set_output_prefix_type(OutputPrefixType::TINK);
  return CleartextKeysetHandle::GetKeysetHandle(keyset);
}

class JwtMacWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(
        Registry::RegisterPrimitiveWrapper(absl::make_unique<JwtMacWrapper>()),
        IsOk());
    ASSERT_THAT(Registry::RegisterKeyTypeManager(
                    absl::make_unique<JwtHmacKeyManager>(), true),
                IsOk());
  }
};

TEST_F(JwtMacWrapperTest, WrapNullptr) {
  util::StatusOr<std::unique_ptr<JwtMac>> mac_result =
      JwtMacWrapper().Wrap(nullptr);
  EXPECT_FALSE(mac_result.ok());
}

TEST_F(JwtMacWrapperTest, WrapEmpty) {
  auto jwt_mac_set = absl::make_unique<PrimitiveSet<JwtMacInternal>>();
  util::StatusOr<std::unique_ptr<crypto::tink::JwtMac>> jwt_mac_result =
      JwtMacWrapper().Wrap(std::move(jwt_mac_set));
  EXPECT_FALSE(jwt_mac_result.ok());
}

TEST_F(JwtMacWrapperTest, CannotWrapPrimitivesFromNonRawOrTinkKeys) {
  KeyTemplate tink_key_template = createTemplate(OutputPrefixType::LEGACY);

  util::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(tink_key_template);
  EXPECT_THAT(keyset_handle, IsOk());

  EXPECT_FALSE((*keyset_handle)->GetPrimitive<JwtMac>().status().ok());
}

TEST_F(JwtMacWrapperTest, GenerateRawComputeVerifySuccess) {
  KeyTemplate key_template = createTemplate(OutputPrefixType::RAW);
  util::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(key_template);
  EXPECT_THAT(keyset_handle, IsOk());
  util::StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      (*keyset_handle)->GetPrimitive<JwtMac>();
  EXPECT_THAT(jwt_mac, IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("issuer"));

  util::StatusOr<JwtValidator> validator2 = JwtValidatorBuilder()
                                                .ExpectIssuer("unknown")
                                                .AllowMissingExpiration()
                                                .Build();
  ASSERT_THAT(validator2, IsOk());
  util::StatusOr<VerifiedJwt> verified_jwt2 =
      (*jwt_mac)->VerifyMacAndDecode(*compact, *validator2);
  EXPECT_FALSE(verified_jwt2.ok());
  // Make sure the error message is interesting
  EXPECT_THAT(verified_jwt2.status().message(), Eq("wrong issuer"));

  // Raw primitives don't add a kid header, Tink primitives require a kid
  // header to be set. Thefore, changing the output prefix to TINK makes the
  // validation fail.
  std::unique_ptr<KeysetHandle> tink_keyset_handle =
      KeysetHandleWithTinkPrefix(**keyset_handle);
  util::StatusOr<std::unique_ptr<JwtMac>> tink_jwt_mac =
      tink_keyset_handle->GetPrimitive<JwtMac>();
  ASSERT_THAT(tink_jwt_mac, IsOk());

  EXPECT_THAT(
      (*tink_jwt_mac)->VerifyMacAndDecode(*compact, *validator).status(),
      Not(IsOk()));
}

TEST_F(JwtMacWrapperTest, GenerateTinkComputeVerifySuccess) {
  KeyTemplate key_template = createTemplate(OutputPrefixType::TINK);
  util::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(key_template);
  EXPECT_THAT(keyset_handle, IsOk());
  util::StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      (*keyset_handle)->GetPrimitive<JwtMac>();
  EXPECT_THAT(jwt_mac, IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  util::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), test::IsOkAndHolds("issuer"));

  // Parse header to make sure that key ID is correctly encoded.
  google::crypto::tink::KeysetInfo keyset_info =
      (*keyset_handle)->GetKeysetInfo();
  uint32_t key_id = keyset_info.key_info(0).key_id();
  std::vector<absl::string_view> parts = absl::StrSplit(*compact, '.');
  ASSERT_THAT(parts.size(), Eq(3));
  std::string json_header;
  ASSERT_TRUE(DecodeHeader(parts[0], &json_header));
  util::StatusOr<google::protobuf::Struct> header =
      JsonStringToProtoStruct(json_header);
  ASSERT_THAT(header, IsOk());
  EXPECT_THAT(GetKeyId((*header).fields().find("kid")->second.string_value()),
              key_id);

  // For Tink primitives, the kid must be correctly set and is verified.
  // Therefore, changing the key_id makes the validation fail.
  std::unique_ptr<KeysetHandle> keyset_handle_with_new_key_id =
      KeysetHandleWithNewKeyId(**keyset_handle);
  util::StatusOr<std::unique_ptr<JwtMac>> jwt_mac_with_new_key_id =
      keyset_handle_with_new_key_id->GetPrimitive<JwtMac>();
  ASSERT_THAT(jwt_mac_with_new_key_id, IsOk());

  util::StatusOr<VerifiedJwt> verified_jwt_2 =
      (*jwt_mac_with_new_key_id)->VerifyMacAndDecode(*compact, *validator);
  EXPECT_FALSE(verified_jwt_2.ok());
}

TEST_F(JwtMacWrapperTest, KeyRotation) {
  std::vector<OutputPrefixType> prefixes = {OutputPrefixType::RAW,
                                            OutputPrefixType::TINK};
  for (OutputPrefixType prefix : prefixes) {
    SCOPED_TRACE(absl::StrCat("Testing with prefix ", prefix));
    KeyTemplate key_template = createTemplate(prefix);
    KeysetManager manager;

    util::StatusOr<uint32_t> old_id = manager.Add(key_template);
    ASSERT_THAT(old_id, IsOk());
    ASSERT_THAT(manager.SetPrimary(*old_id), IsOk());
    std::unique_ptr<KeysetHandle> handle1 = manager.GetKeysetHandle();
    util::StatusOr<std::unique_ptr<JwtMac>> jwt_mac1 =
        handle1->GetPrimitive<JwtMac>();
    ASSERT_THAT(jwt_mac1, IsOk());

    util::StatusOr<uint32_t> new_id = manager.Add(key_template);
    ASSERT_THAT(new_id, IsOk());
    std::unique_ptr<KeysetHandle> handle2 = manager.GetKeysetHandle();
    util::StatusOr<std::unique_ptr<JwtMac>> jwt_mac2 =
        handle2->GetPrimitive<JwtMac>();
    ASSERT_THAT(jwt_mac2, IsOk());

    ASSERT_THAT(manager.SetPrimary(*new_id), IsOk());
    std::unique_ptr<KeysetHandle> handle3 = manager.GetKeysetHandle();
    util::StatusOr<std::unique_ptr<JwtMac>> jwt_mac3 =
        handle3->GetPrimitive<JwtMac>();
    ASSERT_THAT(jwt_mac3, IsOk());

    ASSERT_THAT(manager.Disable(*old_id), IsOk());
    std::unique_ptr<KeysetHandle> handle4 = manager.GetKeysetHandle();
    util::StatusOr<std::unique_ptr<JwtMac>> jwt_mac4 =
        handle4->GetPrimitive<JwtMac>();
    ASSERT_THAT(jwt_mac4, IsOk());

    util::StatusOr<RawJwt> raw_jwt =
        RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
    ASSERT_THAT(raw_jwt, IsOk());
    util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                                 .ExpectIssuer("issuer")
                                                 .AllowMissingExpiration()
                                                 .Build();
    ASSERT_THAT(validator, IsOk());

    util::StatusOr<std::string> compact1 =
        (*jwt_mac1)->ComputeMacAndEncode(*raw_jwt);
    ASSERT_THAT(compact1, IsOk());

    util::StatusOr<std::string> compact2 =
        (*jwt_mac2)->ComputeMacAndEncode(*raw_jwt);
    ASSERT_THAT(compact2, IsOk());

    util::StatusOr<std::string> compact3 =
        (*jwt_mac3)->ComputeMacAndEncode(*raw_jwt);
    ASSERT_THAT(compact3, IsOk());

    util::StatusOr<std::string> compact4 =
        (*jwt_mac4)->ComputeMacAndEncode(*raw_jwt);
    ASSERT_THAT(compact4, IsOk());

    EXPECT_THAT((*jwt_mac1)->VerifyMacAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac3)->VerifyMacAndDecode(*compact1, *validator).status(),
                IsOk());
    EXPECT_FALSE((*jwt_mac4)->VerifyMacAndDecode(*compact1, *validator).ok());

    EXPECT_THAT((*jwt_mac1)->VerifyMacAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac3)->VerifyMacAndDecode(*compact2, *validator).status(),
                IsOk());
    EXPECT_FALSE((*jwt_mac4)->VerifyMacAndDecode(*compact2, *validator).ok());

    EXPECT_FALSE((*jwt_mac1)->VerifyMacAndDecode(*compact3, *validator).ok());
    EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact3, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac3)->VerifyMacAndDecode(*compact3, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac4)->VerifyMacAndDecode(*compact3, *validator).status(),
                IsOk());

    EXPECT_FALSE((*jwt_mac1)->VerifyMacAndDecode(*compact4, *validator).ok());
    EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact4, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac3)->VerifyMacAndDecode(*compact4, *validator).status(),
                IsOk());
    EXPECT_THAT((*jwt_mac4)->VerifyMacAndDecode(*compact4, *validator).status(),
                IsOk());
  }
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
