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

#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid_decrypt.h"
#include "tink/registry.h"
#include "tink/subtle/hybrid_test_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::EciesAeadHkdfKeyFormat;
using ::google::crypto::tink::EciesAeadHkdfPrivateKey;
using ::google::crypto::tink::EciesAeadHkdfPublicKey;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;

namespace {

TEST(EciesAeadHkdfPrivateKeyManagerTest, Basics) {
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().get_version(), Eq(0));
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(
      EciesAeadHkdfPrivateKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(
      EciesAeadHkdfPrivateKeyManager().ValidateKey(EciesAeadHkdfPrivateKey()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

EciesAeadHkdfKeyFormat CreateValidKeyFormat() {
  EciesAeadHkdfKeyFormat key_format;
  key_format.mutable_params()->set_ec_point_format(EcPointFormat::UNCOMPRESSED);
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  *(dem_params->mutable_aead_dem()) = AeadKeyTemplates::Aes128Gcm();
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  kem_params->set_curve_type(EllipticCurveType::NIST_P256);
  kem_params->set_hkdf_hash_type(HashType::SHA256);
  kem_params->set_hkdf_salt("");
  return key_format;
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyFormat) {
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKeyFormat(
                  CreateValidKeyFormat()),
              IsOk());
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyFormatNoPoint) {
  EciesAeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  key_format.mutable_params()->set_ec_point_format(
      EcPointFormat::UNKNOWN_FORMAT);
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyFormatNoDem) {
  EciesAeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  key_format.mutable_params()->mutable_dem_params()->clear_aead_dem();
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyFormatNoKemCurve) {
  EciesAeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  key_format.mutable_params()->mutable_kem_params()->set_curve_type(
      EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyFormatNoKemHash) {
  EciesAeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  key_format.mutable_params()->mutable_kem_params()->set_hkdf_hash_type(
      HashType::UNKNOWN_HASH);
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, CreateKey) {
  EciesAeadHkdfKeyFormat key_format = CreateValidKeyFormat();
  ASSERT_THAT(EciesAeadHkdfPrivateKeyManager().CreateKey(key_format).status(),
              IsOk());
  EciesAeadHkdfPrivateKey key =
      EciesAeadHkdfPrivateKeyManager().CreateKey(key_format).value();
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

  EXPECT_THAT(key.public_key().x(), Not(IsEmpty()));
  EXPECT_THAT(key.public_key().y(), Not(IsEmpty()));
  EXPECT_THAT(key.key_value(), Not(IsEmpty()));
}

EciesAeadHkdfPrivateKey CreateValidKey() {
  return EciesAeadHkdfPrivateKeyManager()
      .CreateKey(CreateValidKeyFormat())
      .value();
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyEmpty) {
  EXPECT_THAT(
      EciesAeadHkdfPrivateKeyManager().ValidateKey(EciesAeadHkdfPrivateKey()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKey) {
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKey(CreateValidKey()),
              IsOk());
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyWrongVersion) {
  EciesAeadHkdfPrivateKey key = CreateValidKey();
  key.set_version(1);
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyNoPoint) {
  EciesAeadHkdfPrivateKey key = CreateValidKey();
  key.mutable_public_key()->mutable_params()->set_ec_point_format(
      EcPointFormat::UNKNOWN_FORMAT);
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyNoDem) {
  EciesAeadHkdfPrivateKey key = CreateValidKey();
  key.mutable_public_key()
      ->mutable_params()
      ->mutable_dem_params()
      ->clear_aead_dem();
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyNoKemCurve) {
  EciesAeadHkdfPrivateKey key = CreateValidKey();
  key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_curve_type(EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, ValidateKeyNoKemHash) {
  EciesAeadHkdfPrivateKey key = CreateValidKey();
  key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_hkdf_hash_type(HashType::UNKNOWN_HASH);
  EXPECT_THAT(EciesAeadHkdfPrivateKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, GetPublicKey) {
  EciesAeadHkdfPrivateKey key = CreateValidKey();
  ASSERT_THAT(EciesAeadHkdfPrivateKeyManager().GetPublicKey(key).status(),
              IsOk());
  EciesAeadHkdfPublicKey public_key =
      EciesAeadHkdfPrivateKeyManager().GetPublicKey(key).value();
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

  EXPECT_THAT(public_key.x(), Not(IsEmpty()));
  EXPECT_THAT(public_key.y(), Not(IsEmpty()));
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, Create) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
      absl::make_unique<AesGcmKeyManager>(), true), IsOk());

  EciesAeadHkdfPrivateKey private_key = CreateValidKey();
  EciesAeadHkdfPublicKey public_key =
      EciesAeadHkdfPrivateKeyManager().GetPublicKey(private_key).value();

  auto decrypt_or =
      EciesAeadHkdfPrivateKeyManager().GetPrimitive<HybridDecrypt>(private_key);
  ASSERT_THAT(decrypt_or, IsOk());
  auto encrypt_or = EciesAeadHkdfHybridEncrypt::New(public_key);
  ASSERT_THAT(encrypt_or, IsOk());

  ASSERT_THAT(HybridEncryptThenDecrypt(encrypt_or.value().get(),
                                       decrypt_or.value().get(), "some text",
                                       "some aad"),
              IsOk());
}

TEST(EciesAeadHkdfPrivateKeyManagerTest, CreateDifferentKey) {
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
      absl::make_unique<AesGcmKeyManager>(), true), IsOk());

  EciesAeadHkdfPrivateKey private_key = CreateValidKey();
  // Note: we create a new private key in the next line.
  EciesAeadHkdfPublicKey public_key =
      EciesAeadHkdfPrivateKeyManager().GetPublicKey(CreateValidKey()).value();

  auto decrypt_or =
      EciesAeadHkdfPrivateKeyManager().GetPrimitive<HybridDecrypt>(private_key);
  ASSERT_THAT(decrypt_or, IsOk());
  auto encrypt_or = EciesAeadHkdfHybridEncrypt::New(public_key);
  ASSERT_THAT(encrypt_or, IsOk());

  ASSERT_THAT(HybridEncryptThenDecrypt(encrypt_or.value().get(),
                                       decrypt_or.value().get(), "some text",
                                       "some aad"),
              Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
