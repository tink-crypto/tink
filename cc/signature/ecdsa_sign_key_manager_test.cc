// Copyright 2017 Google LLC
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

#include "tink/signature/ecdsa_sign_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
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
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EcdsaParams;
using ::google::crypto::tink::EcdsaPrivateKey;
using ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(EcdsaSignKeyManagerTest, Basic) {
  EXPECT_THAT(EcdsaSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(EcdsaSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(EcdsaSignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"));
}

TEST(EcdsaSignKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(EcdsaKeyFormat()),
              Not(IsOk()));
}

EcdsaKeyFormat CreateValidKeyFormat() {
  EcdsaKeyFormat key_format;
  EcdsaParams* params = key_format.mutable_params();
  params->set_hash_type(HashType::SHA256);
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_encoding(EcdsaSignatureEncoding::DER);
  return key_format;
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormat) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormatUnknownCurve) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), Not(IsOk()));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormatBadHashP256) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_hash_type(HashType::SHA512);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), Not(IsOk()));
  EXPECT_THAT(
      EcdsaSignKeyManager().ValidateKeyFormat(format),
      StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormatBadHashP384) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P384);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), Not(IsOk()));
  EXPECT_THAT(
      EcdsaSignKeyManager().ValidateKeyFormat(format),
      StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyFormatBadHashP521) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  EcdsaParams* params = format.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P521);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKeyFormat(format), Not(IsOk()));
  EXPECT_THAT(
      EcdsaSignKeyManager().ValidateKeyFormat(format),
      StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(EcdsaSignKeyManagerTest, CreateKey) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  StatusOr<EcdsaPrivateKey> key_or = EcdsaSignKeyManager().CreateKey(format);
  ASSERT_THAT(key_or.status(), IsOk());
  EcdsaPrivateKey key = key_or.ValueOrDie();

  EXPECT_THAT(key.version(), Eq(0));

  EXPECT_THAT(key.public_key().version(), Eq(key.version()));
  EXPECT_THAT(key.public_key().params().hash_type(),
              Eq(format.params().hash_type()));
  EXPECT_THAT(key.public_key().params().curve(), Eq(format.params().curve()));
  EXPECT_THAT(key.public_key().params().encoding(),
              Eq(format.params().encoding()));

  EXPECT_THAT(key.public_key().x(), SizeIs(Gt(0)));
  EXPECT_THAT(key.public_key().y(), SizeIs(Gt(0)));

  EXPECT_THAT(key.key_value(), SizeIs(Gt(0)));
}

TEST(EcdsaSignKeyManagerTest, CreateKeyValid) {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  StatusOr<EcdsaPrivateKey> key_or = EcdsaSignKeyManager().CreateKey(format);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key_or.ValueOrDie()), IsOk());
}

EcdsaPrivateKey CreateValidKey() {
  EcdsaKeyFormat format = CreateValidKeyFormat();
  return EcdsaSignKeyManager().CreateKey(format).ValueOrDie();
}

TEST(EcdsaSignKeyManagerTest, ValidateKey) {
  EcdsaPrivateKey key = CreateValidKey();
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP256) {
  EcdsaPrivateKey key = CreateValidKey();
  EcdsaParams* params = key.mutable_public_key()->mutable_params();
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_hash_type(HashType::SHA512);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(
      EcdsaSignKeyManager().ValidateKey(key),
      StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP384) {
  EcdsaPrivateKey key = CreateValidKey();
  EcdsaParams* params = key.mutable_public_key()->mutable_params();
  params->set_curve(EllipticCurveType::NIST_P384);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(
      EcdsaSignKeyManager().ValidateKey(key),
      StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP521) {
  EcdsaPrivateKey key = CreateValidKey();
  EcdsaParams* params = key.mutable_public_key()->mutable_params();
  params->set_curve(EllipticCurveType::NIST_P521);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaSignKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(
      EcdsaSignKeyManager().ValidateKey(key),
      StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(EcdsaSignKeyManagerTest, GetPublicKey) {
  EcdsaPrivateKey key = CreateValidKey();
  StatusOr<EcdsaPublicKey> public_key_or =
      EcdsaSignKeyManager().GetPublicKey(key);

  ASSERT_THAT(public_key_or.status(), IsOk());
  EcdsaPublicKey public_key = public_key_or.ValueOrDie();

  EXPECT_THAT(public_key.version(), Eq(key.public_key().version()));
  EXPECT_THAT(public_key.params().hash_type(),
              Eq(key.public_key().params().hash_type()));
  EXPECT_THAT(public_key.params().curve(),
              Eq(key.public_key().params().curve()));
  EXPECT_THAT(public_key.params().encoding(),
              Eq(key.public_key().params().encoding()));

  EXPECT_THAT(public_key.x(), Eq(key.public_key().x()));
  EXPECT_THAT(public_key.y(), Eq(key.public_key().y()));
}

TEST(EcdsaSignKeyManagerTest, Create) {
  EcdsaPrivateKey private_key = CreateValidKey();
  EcdsaPublicKey public_key =
      EcdsaSignKeyManager().GetPublicKey(private_key).ValueOrDie();

  auto signer_or =
      EcdsaSignKeyManager().GetPrimitive<PublicKeySign>(private_key);
  ASSERT_THAT(signer_or.status(), IsOk());

  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  auto direct_verifier_or = subtle::EcdsaVerifyBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()),
      Enums::ProtoToSubtle(public_key.params().encoding()));
  ASSERT_THAT(direct_verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.ValueOrDie()->Verify(
                  signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
              IsOk());
}

TEST(EcdsaSignKeyManagerTest, CreateDifferentKey) {
  EcdsaPrivateKey private_key = CreateValidKey();
  // Note: we create a new key in the next line.
  EcdsaPublicKey public_key =
      EcdsaSignKeyManager().GetPublicKey(CreateValidKey()).ValueOrDie();

  auto signer_or =
      EcdsaSignKeyManager().GetPrimitive<PublicKeySign>(private_key);
  ASSERT_THAT(signer_or.status(), IsOk());

  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  auto direct_verifier_or = subtle::EcdsaVerifyBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()),
      Enums::ProtoToSubtle(public_key.params().encoding()));
  ASSERT_THAT(direct_verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.ValueOrDie()->Verify(
                  signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
              Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
