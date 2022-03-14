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

#include "tink/experimental/pqcrypto/signature/falcon_sign_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_verify.h"
#include "tink/public_key_verify.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::FalconKeyFormat;
using ::google::crypto::tink::FalconPrivateKey;
using ::google::crypto::tink::FalconPublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

struct FalconTestCase {
  std::string test_name;
  int32_t private_key_size;
  int32_t public_key_size;
};

using FalconSignKeyManagerTest = testing::TestWithParam<FalconTestCase>;

// Helper function that returns a valid falcon key format.
StatusOr<FalconKeyFormat> CreateValidKeyFormat(int32 private_key_size) {
  FalconKeyFormat key_format;
  key_format.set_key_size(private_key_size);

  return key_format;
}

TEST(FalconSignKeyManagerTest, Basic) {
  EXPECT_THAT(FalconSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(FalconSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(FalconSignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.FalconPrivateKey"));
}

TEST_P(FalconSignKeyManagerTest, ValidKeyFormat) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size);
  ASSERT_THAT(key_format.status(), IsOk());

  EXPECT_THAT(FalconSignKeyManager().ValidateKeyFormat(*key_format), IsOk());
}

TEST(FalconSignKeyManagerTest, InvalidKeyFormat) {
  StatusOr<FalconKeyFormat> key_format = CreateValidKeyFormat(0);
  ASSERT_THAT(key_format.status(), IsOk());

  EXPECT_THAT(FalconSignKeyManager().ValidateKeyFormat(*key_format),
              Not(IsOk()));
}

TEST_P(FalconSignKeyManagerTest, CreateKeyValid) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size);
  ASSERT_THAT(key_format.status(), IsOk());

  StatusOr<FalconPrivateKey> private_key =
      FalconSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key.status(), IsOk());

  EXPECT_THAT(FalconSignKeyManager().ValidateKey(*private_key), IsOk());
  EXPECT_THAT(private_key->version(), Eq(0));
  EXPECT_THAT(private_key->public_key().version(), Eq(private_key->version()));
  EXPECT_THAT(private_key->key_value(), SizeIs(test_case.private_key_size));
}

TEST_P(FalconSignKeyManagerTest, PrivateKeyWrongVersion) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size);
  ASSERT_THAT(key_format.status(), IsOk());

  StatusOr<FalconPrivateKey> private_key =
      FalconSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key.status(), IsOk());

  private_key->set_version(1);
  EXPECT_THAT(FalconSignKeyManager().ValidateKey(*private_key), Not(IsOk()));
}

TEST_P(FalconSignKeyManagerTest, CreateKeyAlwaysNew) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size);
  ASSERT_THAT(key_format.status(), IsOk());

  absl::flat_hash_set<std::string> keys;
  int num_tests = 5;
  for (int i = 0; i < num_tests; ++i) {
    StatusOr<FalconPrivateKey> private_key =
        FalconSignKeyManager().CreateKey(*key_format);
    ASSERT_THAT(private_key.status(), IsOk());
    keys.insert(private_key->key_value());
  }
  EXPECT_THAT(keys, SizeIs(num_tests));
}

TEST_P(FalconSignKeyManagerTest, GetPublicKey) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size);
  ASSERT_THAT(key_format.status(), IsOk());

  StatusOr<FalconPrivateKey> private_key =
      FalconSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key.status(), IsOk());

  StatusOr<FalconPublicKey> public_key =
      FalconSignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key.status(), IsOk());

  EXPECT_THAT(public_key->version(), Eq(private_key->public_key().version()));
  EXPECT_THAT(public_key->key_value(),
              Eq(private_key->public_key().key_value()));
}

TEST_P(FalconSignKeyManagerTest, CreateValid) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size);
  ASSERT_THAT(key_format.status(), IsOk());

  util::StatusOr<FalconPrivateKey> private_key =
      FalconSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      FalconSignKeyManager().GetPrimitive<PublicKeySign>(*private_key);
  ASSERT_THAT(signer.status(), IsOk());

  StatusOr<subtle::FalconPublicKeyPqclean> falcon_public_key_pqclean =
      subtle::FalconPublicKeyPqclean::NewPublicKey(
          private_key->public_key().key_value());
  ASSERT_THAT(falcon_public_key_pqclean.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      subtle::FalconVerify::New(*falcon_public_key_pqclean);
  ASSERT_THAT(verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(FalconSignKeyManagerTest, CreateBadPublicKey) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconKeyFormat> key_format =
      CreateValidKeyFormat(test_case.private_key_size);
  ASSERT_THAT(key_format.status(), IsOk());

  util::StatusOr<FalconPrivateKey> private_key =
      FalconSignKeyManager().CreateKey(*key_format);
  ASSERT_THAT(private_key.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      FalconSignKeyManager().GetPrimitive<PublicKeySign>(*private_key);
  ASSERT_THAT(signer.status(), IsOk());

  std::string bad_public_key_data(test_case.public_key_size, '@');

  StatusOr<subtle::FalconPublicKeyPqclean> falcon_public_key_pqclean =
      subtle::FalconPublicKeyPqclean::NewPublicKey(bad_public_key_data);
  ASSERT_THAT(falcon_public_key_pqclean.status(), IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> direct_verifier =
      subtle::FalconVerify::New(*falcon_public_key_pqclean);
  ASSERT_THAT(direct_verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());
  EXPECT_THAT((*direct_verifier)->Verify(*signature, message), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    FalconSignKeyManagerTests, FalconSignKeyManagerTest,
    testing::ValuesIn<FalconTestCase>(
        {{"Falcon512", subtle::kFalcon512PrivateKeySize,
          subtle::kFalcon512PublicKeySize},
         {"Falcon1024", subtle::kFalcon1024PrivateKeySize,
          subtle::kFalcon1024PublicKeySize}}),
    [](const testing::TestParamInfo<FalconSignKeyManagerTest::ParamType>&
           info) { return info.param.test_name; });

}  // namespace

}  // namespace tink
}  // namespace crypto
