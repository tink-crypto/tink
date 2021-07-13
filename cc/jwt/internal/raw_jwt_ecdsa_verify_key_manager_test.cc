// Copyright 2021 Google LLC.
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

#include "tink/jwt/internal/raw_jwt_ecdsa_verify_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/jwt/internal/raw_jwt_ecdsa_sign_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::Enums;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::JwtEcdsaPrivateKey;
using ::google::crypto::tink::JwtEcdsaPublicKey;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

namespace {

TEST(RawJwtEcdsaVerifyKeyManagerTest, Basics) {
  EXPECT_THAT(RawJwtEcdsaVerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RawJwtEcdsaVerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(RawJwtEcdsaVerifyKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey"));
}

TEST(RawJwtEcdsaVerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(RawJwtEcdsaVerifyKeyManager().ValidateKey(JwtEcdsaPublicKey()),
              Not(IsOk()));
}

JwtEcdsaPrivateKey CreateValidEs256PrivateKey() {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  return RawJwtEcdsaSignKeyManager().CreateKey(key_format).ValueOrDie();
}

JwtEcdsaPublicKey CreateValidPublicKey() {
  return RawJwtEcdsaSignKeyManager()
      .GetPublicKey(CreateValidEs256PrivateKey())
      .ValueOrDie();
}

// Checks that a public key generaed by the SignKeyManager is considered valid.
TEST(RawJwtEcdsaVerifyKeyManagerTest, PublicKeyValid) {
  JwtEcdsaPublicKey key = CreateValidPublicKey();
  EXPECT_THAT(RawJwtEcdsaVerifyKeyManager().ValidateKey(key), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyUnknownAlgorithm) {
  JwtEcdsaPublicKey key = CreateValidPublicKey();
  key.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_THAT(RawJwtEcdsaVerifyKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(
      RawJwtEcdsaVerifyKeyManager().ValidateKey(key),
      StatusIs(util::error::INVALID_ARGUMENT));
}


TEST(EcdsaSignKeyManagerTest, Create) {
  JwtEcdsaPrivateKey private_key = CreateValidEs256PrivateKey();
  JwtEcdsaPublicKey public_key =
      RawJwtEcdsaSignKeyManager().GetPublicKey(private_key).ValueOrDie();

  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(EllipticCurveType::NIST_P256);
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  ec_key.priv = util::SecretDataFromStringView(private_key.key_value());

  auto direct_signer_or = subtle::EcdsaSignBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(HashType::SHA256),
      subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(direct_signer_or.status(), IsOk());

  auto verifier_or =
      RawJwtEcdsaVerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(
      verifier_or.ValueOrDie()->Verify(
          direct_signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
      IsOk());
}

TEST(EcdsaSignKeyManagerTest, CreateDifferentPrivateKey) {
  JwtEcdsaPrivateKey private_key = CreateValidEs256PrivateKey();
  // Note: we create a new key in the next line.
  JwtEcdsaPublicKey public_key = RawJwtEcdsaSignKeyManager()
                                     .GetPublicKey(CreateValidEs256PrivateKey())
                                     .ValueOrDie();

  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(EllipticCurveType::NIST_P256);
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  ec_key.priv = util::SecretDataFromStringView(private_key.key_value());

  auto direct_signer_or = subtle::EcdsaSignBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(HashType::SHA256),
      subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(direct_signer_or.status(), IsOk());

  auto verifier_or =
      RawJwtEcdsaVerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(
      verifier_or.ValueOrDie()->Verify(
          direct_signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
      Not(IsOk()));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
