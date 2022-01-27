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

#include "tink/experimental/pqcrypto/signature/falcon_verify_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "tink/experimental/pqcrypto/signature/falcon_sign_key_manager.h"
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

struct FalconTestCase {
  std::string test_name;
  int32_t private_key_size;
  int32_t public_key_size;
};

using FalconVerifyKeyManagerTest = testing::TestWithParam<FalconTestCase>;

// Helper function that returns a valid falcon private key.
StatusOr<FalconPrivateKey> CreateValidPrivateKey(int32 private_key_size) {
  FalconKeyFormat key_format;
  key_format.set_key_size(private_key_size);

  return FalconSignKeyManager().CreateKey(key_format);
}

// Helper function that returns a valid falcon public key.
StatusOr<FalconPublicKey> CreateValidPublicKey(int32 private_key_size) {
  StatusOr<FalconPrivateKey> private_key =
      CreateValidPrivateKey(private_key_size);

  if (!private_key.ok()) return private_key.status();
  return FalconSignKeyManager().GetPublicKey(*private_key);
}

TEST(FalconVerifyKeyManagerTest, Basics) {
  EXPECT_THAT(FalconVerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(FalconVerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(FalconVerifyKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.FalconPublicKey"));
}

TEST(FalconVerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(FalconVerifyKeyManager().ValidateKey(FalconPublicKey()),
              Not(IsOk()));
}

TEST_P(FalconVerifyKeyManagerTest, PublicKeyValid) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconPublicKey> public_key =
      CreateValidPublicKey(test_case.private_key_size);
  ASSERT_THAT(public_key.status(), IsOk());

  EXPECT_THAT(FalconVerifyKeyManager().ValidateKey(*public_key), IsOk());
}

TEST_P(FalconVerifyKeyManagerTest, PublicKeyWrongVersion) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconPublicKey> public_key =
      CreateValidPublicKey(test_case.private_key_size);
  ASSERT_THAT(public_key.status(), IsOk());

  public_key->set_version(1);
  EXPECT_THAT(FalconVerifyKeyManager().ValidateKey(*public_key), Not(IsOk()));
}

TEST_P(FalconVerifyKeyManagerTest, Create) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconPrivateKey> private_key =
      CreateValidPrivateKey(test_case.private_key_size);
  ASSERT_THAT(private_key.status(), IsOk());

  StatusOr<FalconPublicKey> public_key =
      FalconSignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key.status(), IsOk());

  StatusOr<subtle::FalconPrivateKeyPqclean> falcon_private_key_pqclean =
      subtle::FalconPrivateKeyPqclean::NewPrivateKey(
          util::SecretDataFromStringView(private_key->key_value()));

  util::StatusOr<std::unique_ptr<PublicKeySign>> direct_signer =
      subtle::FalconSign::New(*falcon_private_key_pqclean);
  ASSERT_THAT(direct_signer.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      FalconVerifyKeyManager().GetPrimitive<PublicKeyVerify>(*public_key);
  ASSERT_THAT(verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*direct_signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(FalconVerifyKeyManagerTest, CreateInvalidPublicKey) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconPrivateKey> private_key =
      CreateValidPrivateKey(test_case.private_key_size);
  ASSERT_THAT(private_key.status(), IsOk());

  StatusOr<FalconPublicKey> public_key =
      FalconSignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key.status(), IsOk());

  std::string bad_public_key_data = "bad_public_key";
  public_key->set_key_value(bad_public_key_data);

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      FalconVerifyKeyManager().GetPrimitive<PublicKeyVerify>(*public_key);
  EXPECT_THAT(verifier.status(), Not(IsOk()));
}

TEST_P(FalconVerifyKeyManagerTest, CreateDifferentPublicKey) {
  const FalconTestCase& test_case = GetParam();

  StatusOr<FalconPrivateKey> private_key =
      CreateValidPrivateKey(test_case.private_key_size);
  ASSERT_THAT(private_key.status(), IsOk());

  // Create a new public key derived from a diffferent private key.
  StatusOr<FalconPrivateKey> new_private_key =
      CreateValidPrivateKey(test_case.private_key_size);
  ASSERT_THAT(new_private_key.status(), IsOk());
  StatusOr<FalconPublicKey> public_key =
      FalconSignKeyManager().GetPublicKey(*new_private_key);
  ASSERT_THAT(public_key.status(), IsOk());

  StatusOr<subtle::FalconPrivateKeyPqclean> falcon_private_key_pqclean =
      subtle::FalconPrivateKeyPqclean::NewPrivateKey(
          util::SecretDataFromStringView(private_key->key_value()));

  util::StatusOr<std::unique_ptr<PublicKeySign>> direct_signer =
      subtle::FalconSign::New(*falcon_private_key_pqclean);
  ASSERT_THAT(direct_signer.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      FalconVerifyKeyManager().GetPrimitive<PublicKeyVerify>(*public_key);
  ASSERT_THAT(verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*direct_signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    FalconVeirfyKeyManagerTests, FalconVerifyKeyManagerTest,
    testing::ValuesIn<FalconTestCase>(
        {{"Falcon512", subtle::kFalcon512PrivateKeySize,
          subtle::kFalcon512PublicKeySize},
         {"Falcon1024", subtle::kFalcon1024PrivateKeySize,
          subtle::kFalcon1024PublicKeySize}}),
    [](const testing::TestParamInfo<FalconVerifyKeyManagerTest::ParamType>&
           info) { return info.param.test_name; });

}  // namespace

}  // namespace tink
}  // namespace crypto
