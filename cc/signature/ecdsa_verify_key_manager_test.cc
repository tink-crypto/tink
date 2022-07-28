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

#include "tink/signature/ecdsa_verify_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/internal/ec_util.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/ecdsa.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::Enums;
using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EcdsaParams;
using ::google::crypto::tink::EcdsaPrivateKey;
using ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

namespace {

TEST(EcdsaVerifyKeyManagerTest, Basics) {
  EXPECT_THAT(EcdsaVerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(EcdsaVerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(EcdsaVerifyKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.EcdsaPublicKey"));
}

TEST(EcdsaVerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(EcdsaPublicKey()),
              Not(IsOk()));
}

EcdsaPrivateKey CreateValidPrivateKey() {
  EcdsaKeyFormat key_format;
  EcdsaParams* params = key_format.mutable_params();
  params->set_hash_type(HashType::SHA256);
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_encoding(EcdsaSignatureEncoding::DER);
  return EcdsaSignKeyManager().CreateKey(key_format).value();
}

EcdsaPublicKey CreateValidPublicKey() {
  return EcdsaSignKeyManager().GetPublicKey(CreateValidPrivateKey()).value();
}

// Checks that a public key generaed by the SignKeyManager is considered valid.
TEST(EcdsaVerifyKeyManagerTest, PublicKeyValid) {
  EcdsaPublicKey key = CreateValidPublicKey();
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP256) {
  EcdsaPublicKey key = CreateValidPublicKey();
  EcdsaParams* params = key.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_hash_type(HashType::SHA512);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP384) {
  EcdsaPublicKey key = CreateValidPublicKey();
  EcdsaParams* params = key.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P384);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP521) {
  EcdsaPublicKey key = CreateValidPublicKey();
  EcdsaParams* params = key.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P521);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateParams) {
  EcdsaParams params;
  params.set_hash_type(HashType::SHA256);
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateParamsHashP384) {
  EcdsaParams params;
  params.set_hash_type(HashType::SHA384);
  params.set_curve(EllipticCurveType::NIST_P384);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateParamsBadHashP256) {
  EcdsaParams params;
  params.set_hash_type(HashType::SHA512);
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateParamsBadHashP384) {
  EcdsaParams params;
  params.set_curve(EllipticCurveType::NIST_P384);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateParamsBadHashP521) {
  EcdsaParams params;
  params.set_curve(EllipticCurveType::NIST_P521);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, Create) {
  EcdsaPrivateKey private_key = CreateValidPrivateKey();
  EcdsaPublicKey public_key =
      EcdsaSignKeyManager().GetPublicKey(private_key).value();

  internal::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  ec_key.priv = util::SecretDataFromStringView(private_key.key_value());

  auto direct_signer_or = subtle::EcdsaSignBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()),
      Enums::ProtoToSubtle(public_key.params().encoding()));
  ASSERT_THAT(direct_signer_or, IsOk());

  auto verifier_or =
      EcdsaVerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(verifier_or.value()->Verify(
                  direct_signer_or.value()->Sign(message).value(), message),
              IsOk());
}

TEST(EcdsaSignKeyManagerTest, CreateDifferentPrivateKey) {
  EcdsaPrivateKey private_key = CreateValidPrivateKey();
  // Note: we create a new key in the next line.
  EcdsaPublicKey public_key =
      EcdsaSignKeyManager().GetPublicKey(CreateValidPrivateKey()).value();

  internal::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  ec_key.priv = util::SecretDataFromStringView(private_key.key_value());

  auto direct_signer_or = subtle::EcdsaSignBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()),
      Enums::ProtoToSubtle(public_key.params().encoding()));
  ASSERT_THAT(direct_signer_or, IsOk());

  auto verifier_or =
      EcdsaVerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(verifier_or.value()->Verify(
                  direct_signer_or.value()->Sign(message).value(), message),
              Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
