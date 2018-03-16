// Copyright 2017 Google Inc.
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

#include "tink/signature/public_key_sign_set_wrapper.h"
#include "tink/public_key_sign.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

using crypto::tink::test::DummyPublicKeySign;
using crypto::tink::test::DummyPublicKeyVerify;
using google::crypto::tink::OutputPrefixType;
using google::crypto::tink::Keyset;

namespace crypto {
namespace tink {
namespace {

class PublicKeySignSetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(PublicKeySignSetWrapperTest, testBasic) {
  { // pk_sign_set is nullptr.
    auto pk_sign_result =
        PublicKeySignSetWrapper::NewPublicKeySign(nullptr);
    EXPECT_FALSE(pk_sign_result.ok());
    EXPECT_EQ(util::error::INTERNAL, pk_sign_result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
        pk_sign_result.status().error_message());
  }

  { // pk_sign_set has no primary primitive.
    std::unique_ptr<PrimitiveSet<PublicKeySign>>
        pk_sign_set(new PrimitiveSet<PublicKeySign>());
    auto pk_sign_result =
        PublicKeySignSetWrapper::NewPublicKeySign(std::move(pk_sign_set));
    EXPECT_FALSE(pk_sign_result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT,
        pk_sign_result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
        pk_sign_result.status().error_message());
  }

  { // Correct pk_sign_set;
    Keyset::Key* key;
    Keyset keyset;

    uint32_t key_id_0 = 1234543;
    key = keyset.add_key();
    key->set_output_prefix_type(OutputPrefixType::RAW);
    key->set_key_id(key_id_0);

    uint32_t key_id_1 = 726329;
    key = keyset.add_key();
    key->set_output_prefix_type(OutputPrefixType::LEGACY);
    key->set_key_id(key_id_1);

    uint32_t key_id_2 = 7213743;
    key = keyset.add_key();
    key->set_output_prefix_type(OutputPrefixType::TINK);
    key->set_key_id(key_id_2);

    std::string signature_name_0 = "signature_0";
    std::string signature_name_1 = "signature_1";
    std::string signature_name_2 = "signature_2";
    std::unique_ptr<PrimitiveSet<PublicKeySign>> pk_sign_set(
        new PrimitiveSet<PublicKeySign>());

    std::unique_ptr<PublicKeySign> pk_sign(
        new DummyPublicKeySign(signature_name_0));
    auto entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset.key(0));
    ASSERT_TRUE(entry_result.ok());

    pk_sign.reset(new DummyPublicKeySign(signature_name_1));
    entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset.key(1));
    ASSERT_TRUE(entry_result.ok());

    pk_sign.reset(new DummyPublicKeySign(signature_name_2));
    entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset.key(2));
    ASSERT_TRUE(entry_result.ok());

    // The last key is the primary.
    pk_sign_set->set_primary(entry_result.ValueOrDie());

    // Wrap pk_sign_set and test the resulting PublicKeySign.
    auto pk_sign_result = PublicKeySignSetWrapper::NewPublicKeySign(
        std::move(pk_sign_set));
    EXPECT_TRUE(pk_sign_result.ok()) << pk_sign_result.status();
    pk_sign = std::move(pk_sign_result.ValueOrDie());
    std::string data = "some data to sign";
    auto sign_result = pk_sign->Sign(data);
    EXPECT_TRUE(sign_result.ok()) << sign_result.status();
    std::string signature = sign_result.ValueOrDie();
    std::unique_ptr<PublicKeyVerify> pk_verify(
        new DummyPublicKeyVerify(signature_name_2));
    auto verify_status = pk_verify->Verify(signature, data);
    EXPECT_TRUE(verify_status.ok()) << verify_status;
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
