// Copyright 2019 Google Inc.
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

#include "tink/signature/ed25519_verify_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/signature/ed25519_sign_key_manager.h"
#include "tink/subtle/ed25519_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/ed25519.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::Ed25519KeyFormat;
using ::google::crypto::tink::Ed25519PrivateKey;
using ::google::crypto::tink::Ed25519PublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

namespace {

TEST(Ed25519VerifyKeyManagerTest, Basics) {
  EXPECT_THAT(Ed25519VerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(Ed25519VerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(Ed25519VerifyKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.Ed25519PublicKey"));
}

TEST(Ed25519VerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(Ed25519VerifyKeyManager().ValidateKey(Ed25519PublicKey()),
              Not(IsOk()));
}

Ed25519PrivateKey CreateValidPrivateKey() {
  return Ed25519SignKeyManager().CreateKey(Ed25519KeyFormat()).value();
}

Ed25519PublicKey CreateValidPublicKey() {
  return Ed25519SignKeyManager().GetPublicKey(CreateValidPrivateKey()).value();
}

// Checks that a public key generaed by the SignKeyManager is considered valid.
TEST(Ed25519VerifyKeyManagerTest, PublicKeyValid) {
  Ed25519PublicKey key = CreateValidPublicKey();
  EXPECT_THAT(Ed25519VerifyKeyManager().ValidateKey(key), IsOk());
}

TEST(Ed25519VerifyKeyManagerTest, PublicKeyWrongVersion) {
  Ed25519PublicKey key = CreateValidPublicKey();
  key.set_version(1);
  EXPECT_THAT(Ed25519VerifyKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(Ed25519VerifyKeyManagerTest, PublicKeyWrongKeyLength31) {
  Ed25519PublicKey key = CreateValidPublicKey();
  key.set_key_value(std::string(31, 'a'));
  EXPECT_THAT(Ed25519VerifyKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(Ed25519VerifyKeyManagerTest, PublicKeyWrongKeyLength64) {
  Ed25519PublicKey key = CreateValidPublicKey();
  key.set_key_value(std::string(64, 'a'));
  EXPECT_THAT(Ed25519VerifyKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(Ed25519SignKeyManagerTest, Create) {
  Ed25519PrivateKey private_key = CreateValidPrivateKey();
  Ed25519PublicKey public_key =
      Ed25519SignKeyManager().GetPublicKey(private_key).value();

  auto direct_signer_or =
      subtle::Ed25519SignBoringSsl::New(util::SecretDataFromStringView(
          absl::StrCat(private_key.key_value(), public_key.key_value())));
  ASSERT_THAT(direct_signer_or, IsOk());

  auto verifier_or =
      Ed25519VerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(verifier_or.value()->Verify(
                  direct_signer_or.value()->Sign(message).value(), message),
              IsOk());
}

TEST(Ed25519SignKeyManagerTest, CreateDifferentPrivateKey) {
  Ed25519PrivateKey private_key = CreateValidPrivateKey();
  // Note: we create a new key in the next line.
  Ed25519PublicKey public_key =
      Ed25519SignKeyManager().GetPublicKey(CreateValidPrivateKey()).value();

  auto direct_signer_or = subtle::Ed25519SignBoringSsl::New(
      util::SecretDataFromStringView(absl::StrCat(
          private_key.key_value(), private_key.public_key().key_value())));
  ASSERT_THAT(direct_signer_or, IsOk());

  auto verifier_or =
      Ed25519VerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(verifier_or.value()->Verify(
                  direct_signer_or.value()->Sign(message).value(), message),
              Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
