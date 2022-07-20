// Copyright 2018 Google Inc.
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

#include "tink/hybrid/hybrid_key_templates.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/hybrid_config.h"
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::HpkePrivateKeyManager;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::EciesAeadHkdfKeyFormat;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;

class HybridKeyTemplatesTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    // Initialize the registry, so that the templates can be tested.
    ASSERT_THAT(HybridConfig::Register(), IsOk());
  }
};

TEST_F(HybridKeyTemplatesTest, EciesP256HkdfHmacSha256Aes128Gcm) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::UNCOMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128Gcm();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::NIST_P256, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, EciesP256HkdfHmacSha512Aes128Gcm) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128Gcm();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::UNCOMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128Gcm();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::NIST_P256, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA512, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128Gcm();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest,
       EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template = HybridKeyTemplates::
      EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::RAW, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::COMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128Gcm();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::NIST_P256, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 = HybridKeyTemplates::
      EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, EciesP256HkdfHmacSha256Aes128CtrHmacSha256) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::UNCOMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128CtrHmacSha256();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::NIST_P256, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, EciesP256HkdfHmacSha512Aes128CtrHmacSha256) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128CtrHmacSha256();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::UNCOMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128CtrHmacSha256();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::NIST_P256, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA512, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128CtrHmacSha256();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, EciesP256CompressedHkdfHmacSha256Aes128Gcm) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128Gcm();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::COMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128Gcm();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::NIST_P256, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128Gcm();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest,
       EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template = HybridKeyTemplates::
      EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::COMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128CtrHmacSha256();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::NIST_P256, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 = HybridKeyTemplates::
      EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, EciesX25519HkdfHmacSha256Aes128Gcm) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128Gcm();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::COMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128Gcm();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::CURVE25519, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128Gcm();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, EciesX25519HkdfHmacSha256Aes256Gcm) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes256Gcm();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::COMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes256Gcm();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::CURVE25519, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes256Gcm();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest,
       EciesX25519HkdfHmacSha256Aes128CtrHmacSha256) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128CtrHmacSha256();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::COMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::Aes128CtrHmacSha256();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::CURVE25519, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128CtrHmacSha256();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, EciesX25519HkdfHmacSha256XChaCha20Poly1305) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256XChaCha20Poly1305();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::COMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = AeadKeyTemplates::XChaCha20Poly1305();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::CURVE25519, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256XChaCha20Poly1305();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, EciesX25519HkdfHmacSha256DeterministicAesSiv) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256DeterministicAesSiv();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  EciesAeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(EcPointFormat::COMPRESSED, key_format.params().ec_point_format());
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  auto expected_dem = DeterministicAeadKeyTemplates::Aes256Siv();
  EXPECT_EQ(expected_dem.output_prefix_type(),
            dem_params->aead_dem().output_prefix_type());
  EXPECT_EQ(expected_dem.type_url(), dem_params->aead_dem().type_url());
  EXPECT_EQ(expected_dem.value(), dem_params->aead_dem().value());
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  EXPECT_EQ(EllipticCurveType::CURVE25519, kem_params->curve_type());
  EXPECT_EQ(HashType::SHA256, kem_params->hkdf_hash_type());
  EXPECT_EQ("", kem_params->hkdf_salt());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::EciesX25519HkdfHmacSha256DeterministicAesSiv();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  EciesAeadHkdfPrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, HpkeX25519HkdfSha256Aes128Gcm) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  HpkeKeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(key_template.value()));
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().kem(), Eq(HpkeKem::DHKEM_X25519_HKDF_SHA256));
  EXPECT_THAT(key_format.params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(key_format.params().aead(), Eq(HpkeAead::AES_128_GCM));

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  HpkePrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, HpkeX25519HkdfSha256Aes128GcmRaw) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes128GcmRaw();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::RAW, key_template.output_prefix_type());
  HpkeKeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(key_template.value()));
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().kem(), Eq(HpkeKem::DHKEM_X25519_HKDF_SHA256));
  EXPECT_THAT(key_format.params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(key_format.params().aead(), Eq(HpkeAead::AES_128_GCM));

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes128GcmRaw();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  HpkePrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, HpkeX25519HkdfSha256Aes256Gcm) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  HpkeKeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(key_template.value()));
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().kem(), Eq(HpkeKem::DHKEM_X25519_HKDF_SHA256));
  EXPECT_THAT(key_format.params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(key_format.params().aead(), Eq(HpkeAead::AES_256_GCM));

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  HpkePrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, HpkeX25519HkdfSha256Aes256GcmRaw) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes256GcmRaw();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::RAW, key_template.output_prefix_type());
  HpkeKeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(key_template.value()));
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().kem(), Eq(HpkeKem::DHKEM_X25519_HKDF_SHA256));
  EXPECT_THAT(key_format.params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(key_format.params().aead(), Eq(HpkeAead::AES_256_GCM));

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::HpkeX25519HkdfSha256Aes256GcmRaw();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  HpkePrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, HpkeX25519HkdfSha256ChaCha20Poly1305) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  HpkeKeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(key_template.value()));
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().kem(), Eq(HpkeKem::DHKEM_X25519_HKDF_SHA256));
  EXPECT_THAT(key_format.params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(key_format.params().aead(), Eq(HpkeAead::CHACHA20_POLY1305));

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  HpkePrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

TEST_F(HybridKeyTemplatesTest, HpkeX25519HkdfSha256ChaCha20Poly1305Raw) {
  // Check that returned template is correct.
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey";
  const KeyTemplate& key_template =
      HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305Raw();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::RAW, key_template.output_prefix_type());
  HpkeKeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(key_template.value()));
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().kem(), Eq(HpkeKem::DHKEM_X25519_HKDF_SHA256));
  EXPECT_THAT(key_format.params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(key_format.params().aead(), Eq(HpkeAead::CHACHA20_POLY1305));

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305Raw();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  HpkePrivateKeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  EXPECT_THAT(key_manager.ValidateKeyFormat(key_format), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
