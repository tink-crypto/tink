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

#include "tink/signature/public_key_sign_wrapper.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/crypto_format.h"
#include "tink/primitive_set.h"
#include "tink/public_key_sign.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"
#include "tink/util/test_matchers.h"

using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::DummyPublicKeyVerify;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;

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
    auto pk_sign_result = PublicKeySignWrapper().Wrap(nullptr);
    EXPECT_FALSE(pk_sign_result.ok());
    EXPECT_EQ(absl::StatusCode::kInternal, pk_sign_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                        std::string(pk_sign_result.status().message()));
  }

  { // pk_sign_set has no primary primitive.
    std::unique_ptr<PrimitiveSet<PublicKeySign>>
        pk_sign_set(new PrimitiveSet<PublicKeySign>());
    auto pk_sign_result = PublicKeySignWrapper().Wrap(std::move(pk_sign_set));
    EXPECT_FALSE(pk_sign_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
        pk_sign_result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                        std::string(pk_sign_result.status().message()));
  }

  { // Correct pk_sign_set;
    KeysetInfo::KeyInfo* key_info;
    KeysetInfo keyset_info;

    uint32_t key_id_0 = 1234543;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::TINK);
    key_info->set_key_id(key_id_0);
    key_info->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_1 = 726329;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::LEGACY);
    key_info->set_key_id(key_id_1);
    key_info->set_status(KeyStatusType::ENABLED);

    uint32_t key_id_2 = 7213743;
    key_info = keyset_info.add_key_info();
    key_info->set_output_prefix_type(OutputPrefixType::RAW);
    key_info->set_key_id(key_id_2);
    key_info->set_status(KeyStatusType::ENABLED);

    std::string signature_name_0 = "signature_0";
    std::string signature_name_1 = "signature_1";
    std::string signature_name_2 = "signature_2";
    std::unique_ptr<PrimitiveSet<PublicKeySign>> pk_sign_set(
        new PrimitiveSet<PublicKeySign>());

    std::unique_ptr<PublicKeySign> pk_sign(
        new DummyPublicKeySign(signature_name_0));
    auto entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset_info.key_info(0));
    ASSERT_TRUE(entry_result.ok());

    pk_sign = absl::make_unique<DummyPublicKeySign>(signature_name_1);
    entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset_info.key_info(1));
    ASSERT_TRUE(entry_result.ok());

    pk_sign = absl::make_unique<DummyPublicKeySign>(signature_name_2);
    entry_result =
        pk_sign_set->AddPrimitive(std::move(pk_sign), keyset_info.key_info(2));
    ASSERT_TRUE(entry_result.ok());

    // The last key is the primary.
    ASSERT_THAT(pk_sign_set->set_primary(entry_result.ValueOrDie()), IsOk());

    // Wrap pk_sign_set and test the resulting PublicKeySign.
    auto pk_sign_result = PublicKeySignWrapper().Wrap(std::move(pk_sign_set));
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

TEST_F(PublicKeySignSetWrapperTest, testLegacySignatures) {
    // Prepare a set for the wrapper.
    KeysetInfo::KeyInfo key;
    uint32_t key_id = 1234543;
    key.set_output_prefix_type(OutputPrefixType::LEGACY);
    key.set_key_id(key_id);
    key.set_status(KeyStatusType::ENABLED);
    std::string signature_name = "SomeLegacySignatures";

    std::unique_ptr<PrimitiveSet<PublicKeySign>> pk_sign_set(
        new PrimitiveSet<PublicKeySign>());
    std::string data = "Some data to sign";
    std::unique_ptr<PublicKeySign> pk_sign(
        new DummyPublicKeySign(signature_name));
    auto entry_result = pk_sign_set->AddPrimitive(std::move(pk_sign), key);
    ASSERT_TRUE(entry_result.ok());
    ASSERT_THAT(pk_sign_set->set_primary(entry_result.ValueOrDie()), IsOk());

    // Wrap pk_sign_set and test the resulting PublicKeySign.
    auto pk_sign_result = PublicKeySignWrapper().Wrap(std::move(pk_sign_set));
    EXPECT_TRUE(pk_sign_result.ok()) << pk_sign_result.status();
    pk_sign = std::move(pk_sign_result.ValueOrDie());

    // Compute the signature via wrapper.
    auto sign_result = pk_sign->Sign(data);
    EXPECT_TRUE(sign_result.ok()) << sign_result.status();
    std::string signature = sign_result.ValueOrDie();
    EXPECT_PRED_FORMAT2(testing::IsSubstring, signature_name, signature);

    // Try verifying on raw PublicKeyVerify-primitive using original data.
    std::unique_ptr<PublicKeyVerify> raw_pk_verify(
        new DummyPublicKeyVerify(signature_name));
    std::string raw_signature =
        signature.substr(CryptoFormat::kNonRawPrefixSize);
    auto status = raw_pk_verify->Verify(raw_signature, data);
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());

    // Verify on raw PublicKeyVerify-primitive using legacy-formatted data.
    std::string legacy_data = data;
    legacy_data.append(1, CryptoFormat::kLegacyStartByte);
    status = raw_pk_verify->Verify(raw_signature, legacy_data);
    EXPECT_TRUE(status.ok()) << status;
}

}  // namespace
}  // namespace tink
}  // namespace crypto
