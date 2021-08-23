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

#include "tink/experimental/pqcrypto/signature/dilithium_verify_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "tink/experimental/pqcrypto/signature/dilithium_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_verify.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"
#include "tink/public_key_verify.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/avx2/api.h"
}

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::DilithiumPrivateKeyPqclean;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::DilithiumKeyFormat;
using ::google::crypto::tink::DilithiumPrivateKey;
using ::google::crypto::tink::DilithiumPublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

struct DilithiumTestCase {
  std::string test_name;
  int private_key_size = 0;
  int public_key_size = 0;
};

using DilithiumVerifyKeyManagerTest = testing::TestWithParam<DilithiumTestCase>;

// Helper function that returns a valid dilithium private key.
StatusOr<DilithiumPrivateKey> CreateValidPrivateKey(int32 private_key_size) {
  DilithiumKeyFormat key_format;
  key_format.set_key_size(private_key_size);

  return DilithiumSignKeyManager().CreateKey(key_format);
}

// Helper function that returns a valid dilithium public key.
StatusOr<DilithiumPublicKey> CreateValidPublicKey(int32 private_key_size) {
  StatusOr<DilithiumPrivateKey> private_key =
      CreateValidPrivateKey(private_key_size);

  if (!private_key.ok()) return private_key.status();
  return DilithiumSignKeyManager().GetPublicKey(*private_key);
}

TEST(DilithiumVerifyKeyManagerTest, Basics) {
  EXPECT_THAT(DilithiumVerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(DilithiumVerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(DilithiumVerifyKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.DilithiumPublicKey"));
}

TEST(DilithiumVerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(DilithiumVerifyKeyManager().ValidateKey(DilithiumPublicKey()),
              Not(IsOk()));
}

TEST_P(DilithiumVerifyKeyManagerTest, PublicKeyValid) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumPublicKey> public_key =
      CreateValidPublicKey(test_case.private_key_size);
  ASSERT_THAT(public_key.status(), IsOk());

  EXPECT_THAT(DilithiumVerifyKeyManager().ValidateKey(*public_key), IsOk());
}

TEST_P(DilithiumVerifyKeyManagerTest, PublicKeyWrongVersion) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumPublicKey> public_key =
      CreateValidPublicKey(test_case.private_key_size);
  ASSERT_THAT(public_key.status(), IsOk());

  public_key->set_version(1);
  EXPECT_THAT(DilithiumVerifyKeyManager().ValidateKey(*public_key),
              Not(IsOk()));
}

TEST_P(DilithiumVerifyKeyManagerTest, PublicKeyWrongKeyLength) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumPublicKey> public_key =
      CreateValidPublicKey(test_case.private_key_size);
  ASSERT_THAT(public_key.status(), IsOk());

  for (int keysize = 0; keysize < PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES;
       keysize++) {
    public_key->set_key_value(std::string(keysize, '@'));
    EXPECT_THAT(DilithiumVerifyKeyManager().ValidateKey(*public_key),
                Not(IsOk()));
  }
}

TEST_P(DilithiumVerifyKeyManagerTest, Create) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumPrivateKey> private_key =
      CreateValidPrivateKey(test_case.private_key_size);
  ASSERT_THAT(private_key.status(), IsOk());

  StatusOr<DilithiumPublicKey> public_key =
      DilithiumSignKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key.status(), IsOk());

  util::StatusOr<DilithiumPrivateKeyPqclean> dilithium_private_key =
      DilithiumPrivateKeyPqclean::NewPrivateKey(
          util::SecretDataFromStringView(private_key->key_value()));
  ASSERT_THAT(dilithium_private_key.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> direct_signer =
      subtle::DilithiumAvx2Sign::New(*dilithium_private_key);
  ASSERT_THAT(direct_signer.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      DilithiumVerifyKeyManager().GetPrimitive<PublicKeyVerify>(*public_key);
  ASSERT_THAT(verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*direct_signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(DilithiumVerifyKeyManagerTest, CreateDifferentPublicKey) {
  const DilithiumTestCase& test_case = GetParam();

  StatusOr<DilithiumPrivateKey> private_key =
      CreateValidPrivateKey(test_case.private_key_size);
  ASSERT_THAT(private_key.status(), IsOk());

  // Create a new public key derived from a diffferent private key.
  StatusOr<DilithiumPrivateKey> new_private_key =
      CreateValidPrivateKey(test_case.private_key_size);
  ASSERT_THAT(new_private_key.status(), IsOk());
  StatusOr<DilithiumPublicKey> public_key =
      DilithiumSignKeyManager().GetPublicKey(*new_private_key);
  ASSERT_THAT(public_key.status(), IsOk());

  util::StatusOr<DilithiumPrivateKeyPqclean> dilithium_private_key =
      DilithiumPrivateKeyPqclean::NewPrivateKey(
          util::SecretDataFromStringView(private_key->key_value()));
  ASSERT_THAT(dilithium_private_key.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> direct_signer =
      subtle::DilithiumAvx2Sign::New(*dilithium_private_key);
  ASSERT_THAT(direct_signer.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      DilithiumVerifyKeyManager().GetPrimitive<PublicKeyVerify>(*public_key);
  ASSERT_THAT(verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> signature = (*direct_signer)->Sign(message);
  ASSERT_THAT(signature.status(), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    DilithiumVerifyKeyManagerTests, DilithiumVerifyKeyManagerTest,
    testing::ValuesIn<DilithiumTestCase>({
        {"Dilithium2", PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES},
        {"Dilithium3", PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM3_AVX2_CRYPTO_PUBLICKEYBYTES},
        {"Dilithium5", PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES,
         PQCLEAN_DILITHIUM5_AVX2_CRYPTO_PUBLICKEYBYTES},
    }),
    [](const testing::TestParamInfo<DilithiumVerifyKeyManagerTest::ParamType>&
           info) { return info.param.test_name; });

}  // namespace

}  // namespace tink
}  // namespace crypto
