// Copyright 2021 Google LLC
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

#include "tink/experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_private_key_manager.h"

#include <string>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_public_key_manager.h"
#include "tink/hybrid_decrypt.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/experimental/pqcrypto/cecpq2_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::Cecpq2AeadHkdfKeyFormat;
using ::google::crypto::tink::Cecpq2AeadHkdfPrivateKey;
using ::google::crypto::tink::Cecpq2AeadHkdfPublicKey;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;

namespace {

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, Basics) {
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().get_version(), Eq(0));
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(
      Cecpq2AeadHkdfPrivateKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey"));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(
      Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(Cecpq2AeadHkdfPrivateKey()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

Cecpq2AeadHkdfKeyFormat CreateValidKeyFormat() {
  Cecpq2AeadHkdfKeyFormat key_format;
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  *(dem_params->mutable_aead_dem()) = AeadKeyTemplates::Aes256Gcm();
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  kem_params->set_curve_type(EllipticCurveType::CURVE25519);
  kem_params->set_hkdf_hash_type(HashType::SHA256);
  kem_params->set_hkdf_salt("");
  kem_params->set_ec_point_format(EcPointFormat::COMPRESSED);
  return key_format;
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyFormat) {
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKeyFormat(
                  CreateValidKeyFormat()),
              IsOk());
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyFormatNoPoint) {
  Cecpq2AeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  kem_params->set_ec_point_format(EcPointFormat::UNKNOWN_FORMAT);
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyFormatNoDem) {
  Cecpq2AeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  key_format.mutable_params()->mutable_dem_params()->clear_aead_dem();
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyFormatNoKemCurve) {
  Cecpq2AeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  key_format.mutable_params()->mutable_kem_params()->set_curve_type(
      EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyFormatNoKemHash) {
  Cecpq2AeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  key_format.mutable_params()->mutable_kem_params()->set_hkdf_hash_type(
      HashType::UNKNOWN_HASH);
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, CreateKey) {
  Cecpq2AeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  ASSERT_THAT(Cecpq2AeadHkdfPrivateKeyManager().CreateKey(key_format).status(),
              IsOk());
  Cecpq2AeadHkdfPrivateKey key =
      Cecpq2AeadHkdfPrivateKeyManager().CreateKey(key_format).value();
  EXPECT_THAT(key.public_key().params().kem_params().curve_type(),
              Eq(key_format.params().kem_params().curve_type()));
  EXPECT_THAT(key.public_key().params().kem_params().hkdf_hash_type(),
              Eq(key_format.params().kem_params().hkdf_hash_type()));
  EXPECT_THAT(key.public_key().params().dem_params().aead_dem().type_url(),
              Eq(key_format.params().dem_params().aead_dem().type_url()));
  EXPECT_THAT(key.public_key().params().dem_params().aead_dem().value(),
              Eq(key_format.params().dem_params().aead_dem().value()));
  EXPECT_THAT(
      key.public_key().params().dem_params().aead_dem().output_prefix_type(),
      Eq(key_format.params().dem_params().aead_dem().output_prefix_type()));

  // X25519 uses compressed points based on the "x" coordinate only. Therefore,
  // we only validate that the "x" coordinate is not empty here
  EXPECT_THAT(key.public_key().x25519_public_key_x(), Not(IsEmpty()));

  EXPECT_THAT(key.x25519_private_key(), Not(IsEmpty()));
}

Cecpq2AeadHkdfPrivateKey CreateValidKey() {
  return Cecpq2AeadHkdfPrivateKeyManager()
      .CreateKey(CreateValidKeyFormat())
      .value();
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyEmpty) {
  EXPECT_THAT(
      Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(Cecpq2AeadHkdfPrivateKey()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKey) {
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(CreateValidKey()),
              IsOk());
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyWrongVersion) {
  Cecpq2AeadHkdfPrivateKey key = CreateValidKey();
  key.set_version(1);
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyNoPoint) {
  Cecpq2AeadHkdfPrivateKey key = CreateValidKey();
  key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_ec_point_format(EcPointFormat::UNKNOWN_FORMAT);
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyNoDem) {
  Cecpq2AeadHkdfPrivateKey key = CreateValidKey();
  key.mutable_public_key()
      ->mutable_params()
      ->mutable_dem_params()
      ->clear_aead_dem();
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyNoKemCurve) {
  Cecpq2AeadHkdfPrivateKey key = CreateValidKey();
  key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_curve_type(EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidateKeyNoKemHash) {
  Cecpq2AeadHkdfPrivateKey key = CreateValidKey();
  key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_hkdf_hash_type(HashType::UNKNOWN_HASH);
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, GetPublicKey) {
  Cecpq2AeadHkdfPrivateKey key = CreateValidKey();
  ASSERT_THAT(Cecpq2AeadHkdfPrivateKeyManager().GetPublicKey(key).status(),
              IsOk());
  Cecpq2AeadHkdfPublicKey public_key =
      Cecpq2AeadHkdfPrivateKeyManager().GetPublicKey(key).value();
  EXPECT_THAT(public_key.params().kem_params().curve_type(),
              Eq(key.public_key().params().kem_params().curve_type()));
  EXPECT_THAT(public_key.params().kem_params().hkdf_hash_type(),
              Eq(key.public_key().params().kem_params().hkdf_hash_type()));
  EXPECT_THAT(public_key.params().dem_params().aead_dem().type_url(),
              Eq(key.public_key().params().dem_params().aead_dem().type_url()));
  EXPECT_THAT(public_key.params().dem_params().aead_dem().value(),
              Eq(key.public_key().params().dem_params().aead_dem().value()));
  EXPECT_THAT(public_key.params().dem_params().aead_dem().output_prefix_type(),
              Eq(key.public_key()
                     .params()
                     .dem_params()
                     .aead_dem()
                     .output_prefix_type()));

  EXPECT_THAT(public_key.x25519_public_key_x(), Not(IsEmpty()));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, Create) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  Cecpq2AeadHkdfPrivateKey private_key = CreateValidKey();
  Cecpq2AeadHkdfPublicKey public_key =
      Cecpq2AeadHkdfPrivateKeyManager().GetPublicKey(private_key).value();

  auto decrypt_or =
      Cecpq2AeadHkdfPrivateKeyManager().GetPrimitive<HybridDecrypt>(
          private_key);
  ASSERT_THAT(decrypt_or.status(), IsOk());
  auto encrypt_or = Cecpq2AeadHkdfHybridEncrypt::New(public_key);
  ASSERT_THAT(encrypt_or.status(), IsOk());

  std::string plaintext = "some text";
  std::string context_info = "some aad";
  auto ciphertext = encrypt_or.value()->Encrypt(plaintext, context_info);
  ASSERT_THAT(ciphertext.status(), IsOk());
  auto decryption =
      decrypt_or.value()->Decrypt(ciphertext.value(), context_info);
  ASSERT_THAT(decryption.status(), IsOk());
  ASSERT_EQ(decryption.value(), plaintext);
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, CreateDifferentKey) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  Cecpq2AeadHkdfPrivateKey private_key = CreateValidKey();
  // Note: we create a new private key in the next line.
  Cecpq2AeadHkdfPublicKey public_key =
      Cecpq2AeadHkdfPrivateKeyManager().GetPublicKey(CreateValidKey()).value();

  auto decrypt_or =
      Cecpq2AeadHkdfPrivateKeyManager().GetPrimitive<HybridDecrypt>(
          private_key);
  ASSERT_THAT(decrypt_or.status(), IsOk());
  auto encrypt_or = Cecpq2AeadHkdfHybridEncrypt::New(public_key);
  ASSERT_THAT(encrypt_or.status(), IsOk());

  std::string plaintext = "some text";
  std::string context_info = "some aad";
  auto ciphertext = encrypt_or.value()->Encrypt(plaintext, context_info);
  ASSERT_THAT(ciphertext.status(), IsOk());
  auto decryption =
      decrypt_or.value()->Decrypt(ciphertext.value(), context_info);
  ASSERT_THAT(decryption.status(), Not(IsOk()));
}

TEST(Cecpq2AeadHkdfPrivateKeyManagerTest, ValidatePrivateKeyVersion) {
  Cecpq2AeadHkdfPrivateKey sk = CreateValidKey();
  sk.set_version(1);
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKey(sk), Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
