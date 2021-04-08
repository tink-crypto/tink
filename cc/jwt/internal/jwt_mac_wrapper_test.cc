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

#include "gtest/gtest.h"
#include "tink/jwt/internal/jwt_hmac_key_manager.h"
#include "tink/keyset_manager.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::HashType;
using google::crypto::tink::JwtHmacKeyFormat;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::crypto::tink::test::IsOk;

KeyTemplate createTemplate(OutputPrefixType output_prefix) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtHmacKey");
  key_template.set_output_prefix_type(output_prefix);
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_hash_type(HashType::SHA256);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

class JwtMacWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EXPECT_TRUE(
        Registry::RegisterPrimitiveWrapper(absl::make_unique<JwtMacWrapper>())
            .ok());
    EXPECT_TRUE(Registry::RegisterKeyTypeManager(
                    absl::make_unique<JwtHmacKeyManager>(), true)
                    .ok());
  }
};

TEST_F(JwtMacWrapperTest, WrapNullptr) {
  auto mac_result = JwtMacWrapper().Wrap(nullptr);
  EXPECT_FALSE(mac_result.ok());
}

TEST_F(JwtMacWrapperTest, WrapEmpty) {
  std::unique_ptr<PrimitiveSet<JwtMac>> jwt_mac_set(new PrimitiveSet<JwtMac>());
  auto jwt_mac_result = JwtMacWrapper().Wrap(std::move(jwt_mac_set));
  EXPECT_FALSE(jwt_mac_result.ok());
}

TEST_F(JwtMacWrapperTest, CannotWrapPrimitivesFromNonRawKeys) {
  KeyTemplate tink_key_template = createTemplate(OutputPrefixType::TINK);

  auto handle_result = KeysetHandle::GenerateNew(tink_key_template);
  EXPECT_THAT(handle_result.status(), IsOk());
  auto keyset_handle = std::move(handle_result.ValueOrDie());

  EXPECT_FALSE(keyset_handle->GetPrimitive<JwtMac>().status().ok());
}

TEST_F(JwtMacWrapperTest, GenerateComputeVerifySuccess) {
  KeyTemplate key_template = createTemplate(OutputPrefixType::RAW);
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  EXPECT_THAT(handle_result.status(), IsOk());
  auto keyset_handle = std::move(handle_result.ValueOrDie());
  auto jwt_mac_or = keyset_handle->GetPrimitive<JwtMac>();
  EXPECT_THAT(jwt_mac_or.status(), IsOk());
  std::unique_ptr<JwtMac> jwt_mac = std::move(jwt_mac_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  RawJwt raw_jwt = raw_jwt_or.ValueOrDie();

  util::StatusOr<std::string> compact_or =
      jwt_mac->ComputeMacAndEncode(raw_jwt);
  ASSERT_THAT(compact_or.status(), IsOk());
  std::string compact = compact_or.ValueOrDie();

  JwtValidator validator = JwtValidatorBuilder().Build();
  util::StatusOr<VerifiedJwt> verified_jwt_or =
      jwt_mac->VerifyMacAndDecode(compact, validator);
  ASSERT_THAT(verified_jwt_or.status(), IsOk());
  auto verified_jwt = verified_jwt_or.ValueOrDie();
  EXPECT_THAT(verified_jwt.GetIssuer(), test::IsOkAndHolds("issuer"));

  JwtValidator validator2 = JwtValidatorBuilder().SetIssuer("unknown").Build();
  EXPECT_FALSE(jwt_mac->VerifyMacAndDecode(compact, validator2).ok());
}

TEST_F(JwtMacWrapperTest, KeyRotation) {
  KeyTemplate key_template = createTemplate(OutputPrefixType::RAW);
  KeysetManager manager;

  auto old_id_or = manager.Add(key_template);
  ASSERT_THAT(old_id_or.status(), IsOk());
  uint32_t old_id = old_id_or.ValueOrDie();
  ASSERT_THAT(manager.SetPrimary(old_id), IsOk());
  std::unique_ptr<KeysetHandle> handle1 = manager.GetKeysetHandle();
  auto jwt_mac1_or = handle1->GetPrimitive<JwtMac>();
  ASSERT_THAT(jwt_mac1_or.status(), IsOk());
  std::unique_ptr<JwtMac> jwt_mac1 = std::move(jwt_mac1_or.ValueOrDie());

  auto new_id_or = manager.Add(key_template);
  ASSERT_THAT(new_id_or.status(), IsOk());
  uint32_t new_id = new_id_or.ValueOrDie();
  std::unique_ptr<KeysetHandle> handle2 = manager.GetKeysetHandle();
  auto jwt_mac2_or = handle2->GetPrimitive<JwtMac>();
  ASSERT_THAT(jwt_mac2_or.status(), IsOk());
  std::unique_ptr<JwtMac> jwt_mac2 = std::move(jwt_mac2_or.ValueOrDie());

  ASSERT_TRUE(manager.SetPrimary(new_id).ok());
  std::unique_ptr<KeysetHandle> handle3 = manager.GetKeysetHandle();
  auto jwt_mac3_or = handle3->GetPrimitive<JwtMac>();
  ASSERT_THAT(jwt_mac3_or.status(), IsOk());
  std::unique_ptr<JwtMac> jwt_mac3 = std::move(jwt_mac3_or.ValueOrDie());

  ASSERT_TRUE(manager.Disable(old_id).ok());
  std::unique_ptr<KeysetHandle> handle4 = manager.GetKeysetHandle();
  auto jwt_mac4_or = handle4->GetPrimitive<JwtMac>();
  ASSERT_THAT(jwt_mac4_or.status(), IsOk());
  std::unique_ptr<JwtMac> jwt_mac4 = std::move(jwt_mac4_or.ValueOrDie());

  auto raw_jwt_or = RawJwtBuilder().SetIssuer("issuer").Build();
  ASSERT_THAT(raw_jwt_or.status(), IsOk());
  RawJwt raw_jwt = raw_jwt_or.ValueOrDie();
  JwtValidator validator = JwtValidatorBuilder().Build();

  util::StatusOr<std::string> compact1_or =
      jwt_mac1->ComputeMacAndEncode(raw_jwt);
  ASSERT_THAT(compact1_or.status(), IsOk());
  std::string compact1 = compact1_or.ValueOrDie();

  util::StatusOr<std::string> compact2_or =
      jwt_mac2->ComputeMacAndEncode(raw_jwt);
  ASSERT_THAT(compact2_or.status(), IsOk());
  std::string compact2 = compact2_or.ValueOrDie();

  util::StatusOr<std::string> compact3_or =
      jwt_mac3->ComputeMacAndEncode(raw_jwt);
  ASSERT_THAT(compact3_or.status(), IsOk());
  std::string compact3 = compact3_or.ValueOrDie();

  util::StatusOr<std::string> compact4_or =
      jwt_mac4->ComputeMacAndEncode(raw_jwt);
  ASSERT_THAT(compact4_or.status(), IsOk());
  std::string compact4 = compact4_or.ValueOrDie();

  EXPECT_TRUE(jwt_mac1->VerifyMacAndDecode(compact1, validator).ok());
  EXPECT_TRUE(jwt_mac2->VerifyMacAndDecode(compact1, validator).ok());
  EXPECT_TRUE(jwt_mac3->VerifyMacAndDecode(compact1, validator).ok());
  EXPECT_FALSE(jwt_mac4->VerifyMacAndDecode(compact1, validator).ok());

  EXPECT_TRUE(jwt_mac1->VerifyMacAndDecode(compact2, validator).ok());
  EXPECT_TRUE(jwt_mac2->VerifyMacAndDecode(compact2, validator).ok());
  EXPECT_TRUE(jwt_mac3->VerifyMacAndDecode(compact2, validator).ok());
  EXPECT_FALSE(jwt_mac4->VerifyMacAndDecode(compact2, validator).ok());

  EXPECT_FALSE(jwt_mac1->VerifyMacAndDecode(compact3, validator).ok());
  EXPECT_TRUE(jwt_mac2->VerifyMacAndDecode(compact3, validator).ok());
  EXPECT_TRUE(jwt_mac3->VerifyMacAndDecode(compact3, validator).ok());
  EXPECT_TRUE(jwt_mac4->VerifyMacAndDecode(compact3, validator).ok());

  EXPECT_FALSE(jwt_mac1->VerifyMacAndDecode(compact4, validator).ok());
  EXPECT_TRUE(jwt_mac2->VerifyMacAndDecode(compact4, validator).ok());
  EXPECT_TRUE(jwt_mac3->VerifyMacAndDecode(compact4, validator).ok());
  EXPECT_TRUE(jwt_mac4->VerifyMacAndDecode(compact4, validator).ok());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
