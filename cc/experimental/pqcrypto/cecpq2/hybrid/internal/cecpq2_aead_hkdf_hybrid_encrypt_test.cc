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

#include "experimental/pqcrypto/cecpq2/hybrid/internal/cecpq2_aead_hkdf_hybrid_encrypt.h"

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "openssl/curve25519.h"
#include "openssl/hrss.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "experimental/pqcrypto/cecpq2/subtle/cecpq2_subtle_boringssl_util.h"
#include "experimental/pqcrypto/cecpq2/util/test_util.h"
#include "tink/hybrid_encrypt.h"
#include "tink/registry.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/enums.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

namespace crypto {
namespace tink {
namespace {

google::crypto::tink::Cecpq2AeadHkdfPublicKey CreateValidKey() {
  auto cecp2_key_pair = crypto::tink::pqc::GenerateCecpq2Keypair(
                            subtle::EllipticCurveType::CURVE25519)
                            .ValueOrDie();
  google::crypto::tink::Cecpq2AeadHkdfPublicKey sender_key;
  sender_key.set_hrss_public_key_marshalled(
      cecp2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  sender_key.set_x25519_public_key_x(cecp2_key_pair.x25519_key_pair.pub_x);
  sender_key.mutable_params()->mutable_kem_params()->set_curve_type(
      google::crypto::tink::EllipticCurveType::CURVE25519);
  sender_key.mutable_params()->mutable_kem_params()->set_hkdf_hash_type(
      google::crypto::tink::HashType::SHA256);
  sender_key.mutable_params()
      ->mutable_dem_params()
      ->mutable_aead_dem()
      ->set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  return sender_key;
}

TEST(Cecpq2AeadHkdfHybridEncryptTest, ValidKey) {
  google::crypto::tink::Cecpq2AeadHkdfPublicKey sender_key = CreateValidKey();
  auto result = Cecpq2AeadHkdfHybridEncrypt::New(sender_key);
  EXPECT_THAT(result.status(), IsOk());
}

TEST(Cecpq2AeadHkdfHybridEncryptTest, InvalidKeyNoFieldSet) {
  auto result = Cecpq2AeadHkdfHybridEncrypt::New(
      google::crypto::tink::Cecpq2AeadHkdfPublicKey());
  EXPECT_THAT(result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("missing KEM required fields")));
}

TEST(Cecpq2AeadHkdfHybridEncryptTest, InvalidKeySomeFieldsSet) {
  google::crypto::tink::Cecpq2AeadHkdfPublicKey sender_key = CreateValidKey();
  sender_key.set_x25519_public_key_x("");
  auto result(Cecpq2AeadHkdfHybridEncrypt::New(sender_key));
  EXPECT_THAT(result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("missing KEM required fields")));
}

TEST(Cecpq2AeadHkdfHybridEncryptTest, InvalidKeyUnsupportedEcType) {
  google::crypto::tink::Cecpq2AeadHkdfPublicKey sender_key = CreateValidKey();
  sender_key.mutable_params()->mutable_kem_params()->set_curve_type(
      google::crypto::tink::EllipticCurveType::NIST_P256);
  auto result = Cecpq2AeadHkdfHybridEncrypt::New(sender_key);
  EXPECT_THAT(result.status(),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("Unsupported elliptic curve")));
}

TEST(Cecpq2AeadHkdfHybridEncryptTest, InvalidKeyUnsupportedDemKeyType) {
  auto status_or_cecpq2_key =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(status_or_cecpq2_key.status(), IsOk());
  auto cecpq2_key_pair = std::move(status_or_cecpq2_key).ValueOrDie();

  google::crypto::tink::Cecpq2AeadHkdfPublicKey sender_key = CreateValidKey();
  sender_key.mutable_params()
      ->mutable_dem_params()
      ->mutable_aead_dem()
      ->set_type_url("some.type.url/that.is.not.supported");
  auto result(Cecpq2AeadHkdfHybridEncrypt::New(sender_key));
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("Unsupported DEM key type")));
}

TEST(Cecpq2AeadHkdfHybridEncryptTest, Basic) {
  // Prepare an Cecpq2 key
  auto cecpq2_key = CreateValidKey();

  // Register DEM key manager
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());
  std::string dem_key_type = AesGcmKeyManager().get_key_type();

  // Generate and test many keys with various parameters
  std::string plaintext = "some plaintext";
  std::string context_info = "some context info";
  for (auto curve : {google::crypto::tink::EllipticCurveType::CURVE25519}) {
    for (auto ec_point_format :
         {google::crypto::tink::EcPointFormat::COMPRESSED}) {
      for (auto hash_type : {google::crypto::tink::HashType::SHA256,
                             google::crypto::tink::HashType::SHA512}) {
        for (uint32_t aes_gcm_key_size : {16, 32}) {
          SCOPED_TRACE(absl::StrCat(curve, ":", ec_point_format, ":", hash_type,
                                    ":", aes_gcm_key_size));
          cecpq2_key.mutable_params()->mutable_kem_params()->set_curve_type(
              curve);
          cecpq2_key.mutable_params()
              ->mutable_kem_params()
              ->set_ec_point_format(ec_point_format);
          cecpq2_key.mutable_params()->mutable_kem_params()->set_hkdf_hash_type(
              hash_type);

          google::crypto::tink::AesGcmKeyFormat format;
          format.set_key_size(aes_gcm_key_size);
          cecpq2_key.mutable_params()
              ->mutable_dem_params()
              ->mutable_aead_dem()
              ->set_value(format.SerializeAsString());
          cecpq2_key.mutable_params()
              ->mutable_dem_params()
              ->mutable_aead_dem()
              ->set_type_url(
                  "type.googleapis.com/google.crypto.tink.AesGcmKey");
          auto key_or = Cecpq2AeadHkdfHybridEncrypt::New(cecpq2_key);
          ASSERT_THAT(key_or.status(), IsOk());
          std::unique_ptr<HybridEncrypt> hybrid_encrypt(
              std::move(key_or.ValueOrDie()));
          // Use the primitive
          auto encrypt_result =
              hybrid_encrypt->Encrypt(plaintext, context_info);
          EXPECT_THAT(encrypt_result.status(), IsOk());
        }
      }
    }
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
