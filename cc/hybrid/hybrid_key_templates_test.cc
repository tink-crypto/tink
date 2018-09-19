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

#include "tink/aead/aead_key_templates.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/hybrid_config.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::EciesAeadHkdfKeyFormat;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

class HybridKeyTemplatesTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    // Initialize the registry, so that the templates can be tested.
    HybridConfig::Register();
  }
};

TEST_F(HybridKeyTemplatesTest, testEciesAeadHkdf) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

  {  // Test EciesP256HkdfHmacSha256Aes128Gcm().
    // Check that returned template is correct.
    const KeyTemplate& key_template =
        HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EciesAeadHkdfKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(EcPointFormat::UNCOMPRESSED,
              key_format.params().ec_point_format());
    auto dem_params = key_format.mutable_params()->mutable_dem_params();
    auto expected_dem = AeadKeyTemplates::Aes128Gcm();
    EXPECT_EQ(expected_dem.output_prefix_type(),
              dem_params->aead_dem().output_prefix_type());
    EXPECT_EQ(expected_dem.type_url(),
              dem_params->aead_dem().type_url());
    EXPECT_EQ(expected_dem.value(),
              dem_params->aead_dem().value());
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
    auto new_key_result = key_manager.get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test EciesP256HkdfHmacSha256Aes128CtrHmacSha256().
    // Check that returned template is correct.
    const KeyTemplate& key_template =
        HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EciesAeadHkdfKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(EcPointFormat::UNCOMPRESSED,
              key_format.params().ec_point_format());
    auto dem_params = key_format.mutable_params()->mutable_dem_params();
    auto expected_dem = AeadKeyTemplates::Aes128CtrHmacSha256();
    EXPECT_EQ(expected_dem.output_prefix_type(),
              dem_params->aead_dem().output_prefix_type());
    EXPECT_EQ(expected_dem.type_url(),
              dem_params->aead_dem().type_url());
    EXPECT_EQ(expected_dem.value(),
              dem_params->aead_dem().value());
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
    auto new_key_result = key_manager.get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
