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

#include "tink/jwt/internal/raw_jwt_ecdsa_sign_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/jwt/internal/raw_jwt_ecdsa_verify_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
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
namespace jwt_internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::Enums;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::JwtEcdsaPrivateKey;
using ::google::crypto::tink::JwtEcdsaPublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(RawJwtEcdsaSignKeyManagerTest, Basic) {
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"));
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(
      RawJwtEcdsaSignKeyManager().ValidateKeyFormat(JwtEcdsaKeyFormat()),
      Not(IsOk()));
}

JwtEcdsaKeyFormat CreateValidEs256KeyFormat() {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  return key_format;
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateKeyFormat) {
  JwtEcdsaKeyFormat format = CreateValidEs256KeyFormat();
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKeyFormat(format), IsOk());
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateKeyFormatUnknownAlgorithm) {
  JwtEcdsaKeyFormat key_format = CreateValidEs256KeyFormat();
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RawJwtEcdsaSignKeyManagerTest, CreateKey) {
  JwtEcdsaKeyFormat format = CreateValidEs256KeyFormat();
  StatusOr<JwtEcdsaPrivateKey> key =
      RawJwtEcdsaSignKeyManager().CreateKey(format);
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->version(), Eq(0));

  EXPECT_THAT(key->public_key().version(), Eq(key->version()));
  EXPECT_THAT(key->public_key().algorithm(),
              Eq(format.algorithm()));

  EXPECT_THAT(key->public_key().x(), SizeIs(Gt(0)));
  EXPECT_THAT(key->public_key().y(), SizeIs(Gt(0)));

  EXPECT_THAT(key->key_value(), SizeIs(Gt(0)));
}

TEST(RawJwtEcdsaSignKeyManagerTest, CreateKeyValid) {
  JwtEcdsaKeyFormat format = CreateValidEs256KeyFormat();
  StatusOr<JwtEcdsaPrivateKey> key =
      RawJwtEcdsaSignKeyManager().CreateKey(format);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKey(*key),
              IsOk());
}

JwtEcdsaPrivateKey CreateValidEs256Key() {
  JwtEcdsaKeyFormat format = CreateValidEs256KeyFormat();
  return RawJwtEcdsaSignKeyManager().CreateKey(format).ValueOrDie();
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateKey) {
  JwtEcdsaPrivateKey key = CreateValidEs256Key();
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKey(key), IsOk());
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateKeyUnknownAlgorithm) {
  JwtEcdsaPrivateKey key = CreateValidEs256Key();
  key.mutable_public_key()->set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RawJwtEcdsaSignKeyManagerTest, GetPublicKey) {
  JwtEcdsaPrivateKey key = CreateValidEs256Key();
  StatusOr<JwtEcdsaPublicKey> public_key =
      RawJwtEcdsaSignKeyManager().GetPublicKey(key);

  ASSERT_THAT(public_key.status(), IsOk());

  EXPECT_THAT(public_key->version(), Eq(key.public_key().version()));
  EXPECT_THAT(public_key->algorithm(),
              Eq(key.public_key().algorithm()));

  EXPECT_THAT(public_key->x(), Eq(key.public_key().x()));
  EXPECT_THAT(public_key->y(), Eq(key.public_key().y()));
}

TEST(RawJwtEcdsaSignKeyManagerTest, Create) {
  JwtEcdsaPrivateKey private_key = CreateValidEs256Key();
  util::StatusOr<JwtEcdsaPublicKey> public_key =
      RawJwtEcdsaSignKeyManager().GetPublicKey(private_key);
  ASSERT_THAT(public_key.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RawJwtEcdsaSignKeyManager().GetPrimitive<PublicKeySign>(private_key);
  ASSERT_THAT(signer.status(), IsOk());

  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(EllipticCurveType::NIST_P256);
  ec_key.pub_x = public_key->x();
  ec_key.pub_y = public_key->y();
  util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>>
      direct_verifier = subtle::EcdsaVerifyBoringSsl::New(
          ec_key, Enums::ProtoToSubtle(HashType::SHA256),
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(direct_verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> sig = (*signer)->Sign(message);
  ASSERT_THAT(sig.status(), IsOk());
  EXPECT_THAT((*direct_verifier)->Verify(*sig, message), IsOk());
}

TEST(RawJwtEcdsaSignKeyManagerTest, CreateDifferentKey) {
  JwtEcdsaPrivateKey private_key = CreateValidEs256Key();
  // Note: we create a new key in the next line.
  util::StatusOr<JwtEcdsaPublicKey> public_key = RawJwtEcdsaSignKeyManager()
                                     .GetPublicKey(CreateValidEs256Key());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RawJwtEcdsaSignKeyManager().GetPrimitive<PublicKeySign>(private_key);
  ASSERT_THAT(signer.status(), IsOk());

  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(EllipticCurveType::NIST_P256);
  ec_key.pub_x = public_key->x();
  ec_key.pub_y = public_key->y();
  util::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>>
      direct_verifier = subtle::EcdsaVerifyBoringSsl::New(
          ec_key, Enums::ProtoToSubtle(HashType::SHA256),
          subtle::EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(direct_verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> sig = (*signer)->Sign(message);
  ASSERT_THAT(sig.status(), IsOk());
  EXPECT_THAT((*direct_verifier)->Verify(*sig, message), Not(IsOk()));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
