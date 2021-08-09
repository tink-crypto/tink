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
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/sign.h"
}

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::DilithiumPrivateKeyPqclean;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::DilithiumKeyFormat;
using ::google::crypto::tink::DilithiumPrivateKey;
using ::google::crypto::tink::DilithiumPublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

namespace {

// Helper function that returns a valid dilithium private key.
StatusOr<DilithiumPrivateKey> CreateValidPrivateKey() {
  return DilithiumSignKeyManager().CreateKey(DilithiumKeyFormat());
}

// Helper function that returns a valid dilithium public key.
StatusOr<DilithiumPublicKey> CreateValidPublicKey() {
  StatusOr<DilithiumPrivateKey> private_key = CreateValidPrivateKey();

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

TEST(DilithiumVerifyKeyManagerTest, PublicKeyValid) {
  StatusOr<DilithiumPublicKey> public_key = CreateValidPublicKey();
  ASSERT_THAT(public_key.status(), IsOk());

  EXPECT_THAT(DilithiumVerifyKeyManager().ValidateKey(*public_key), IsOk());
}

TEST(DilithiumVerifyKeyManagerTest, PublicKeyWrongVersion) {
  StatusOr<DilithiumPublicKey> public_key = CreateValidPublicKey();
  ASSERT_THAT(public_key.status(), IsOk());

  public_key->set_version(1);
  EXPECT_THAT(DilithiumVerifyKeyManager().ValidateKey(*public_key),
              Not(IsOk()));
}

TEST(DilithiumVerifyKeyManagerTest, PublicKeyWrongKeyLength) {
  StatusOr<DilithiumPublicKey> public_key = CreateValidPublicKey();
  ASSERT_THAT(public_key.status(), IsOk());

  for (int keysize = 0; keysize < PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES;
       keysize++) {
    public_key->set_key_value(std::string(keysize, '@'));
    EXPECT_THAT(DilithiumVerifyKeyManager().ValidateKey(*public_key),
                Not(IsOk()));
  }
}

TEST(DilithiumVerifyKeyManagerTest, Create) {
  StatusOr<DilithiumPrivateKey> private_key = CreateValidPrivateKey();
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

TEST(DilithiumVerifyKeyManagerTest, CreateDifferentPublicKey) {
  StatusOr<DilithiumPrivateKey> private_key = CreateValidPrivateKey();
  ASSERT_THAT(private_key.status(), IsOk());

  // Create a new public key derived from a diffferent private key.
  StatusOr<DilithiumPrivateKey> new_private_key = CreateValidPrivateKey();
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

}  // namespace

}  // namespace tink
}  // namespace crypto
