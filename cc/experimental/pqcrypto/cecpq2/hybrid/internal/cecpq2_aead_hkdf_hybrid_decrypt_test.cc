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

#include "experimental/pqcrypto/cecpq2/hybrid/internal/cecpq2_aead_hkdf_hybrid_decrypt.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/match.h"
#include "openssl/curve25519.h"
#include "openssl/hrss.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/config/tink_config.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "experimental/pqcrypto/cecpq2/hybrid/internal/cecpq2_aead_hkdf_hybrid_encrypt.h"
#include "experimental/pqcrypto/cecpq2/subtle/cecpq2_subtle_boringssl_util.h"
#include "experimental/pqcrypto/cecpq2/util/test_util.h"
#include "tink/hybrid_decrypt.h"
#include "tink/registry.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/experimental/pqcrypto/cecpq2_aead_hkdf.pb.h"

using crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

namespace crypto {
namespace tink {
namespace {

class Cecpq2AeadHkdfHybridDecryptTest : public ::testing::Test {
 protected:
  struct CommonHybridKeyParams {
    subtle::EllipticCurveType ec_curve;
    subtle::EcPointFormat ec_point_format;
    subtle::HashType hash_type;
  };

  std::vector<CommonHybridKeyParams> GetCommonHybridKeyParamsList() {
    std::vector<CommonHybridKeyParams> params_list;
    for (auto ec_curve : {subtle::EllipticCurveType::CURVE25519}) {
      for (auto ec_point_format : {subtle::EcPointFormat::COMPRESSED}) {
        for (auto hash_type :
             {subtle::HashType::SHA256, subtle::HashType::SHA512}) {
          CommonHybridKeyParams params;
          params.ec_curve = ec_curve;
          params.ec_point_format = ec_point_format;
          params.hash_type = hash_type;
          params_list.push_back(params);
        }
      }
    }
    return params_list;
  }

  util::Status CheckKeyValidity(
      const google::crypto::tink::Cecpq2AeadHkdfPrivateKey& cecpq2_key) {
    auto result = Cecpq2AeadHkdfHybridDecrypt::New(cecpq2_key);
    if (!result.ok()) return result.status();

    std::unique_ptr<HybridDecrypt> hybrid_decrypt(
        std::move(result.ValueOrDie()));
    std::unique_ptr<HybridEncrypt> hybrid_encrypt(
        std::move(Cecpq2AeadHkdfHybridEncrypt::New(cecpq2_key.public_key())
                      .ValueOrDie()));

    std::string context_info = "some context info";
    for (uint32_t plaintext_size : {0, 1, 10, 100, 1000}) {
      // Use the primitive
      std::string plaintext = Random::GetRandomBytes(plaintext_size);
      auto ciphertext_or = hybrid_encrypt->Encrypt(plaintext, context_info);
      if (!ciphertext_or.ok()) return ciphertext_or.status();
      auto ciphertext = ciphertext_or.ValueOrDie();
      {  // Regular decryption
        auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
        if (!decrypt_result.ok()) {
          return decrypt_result.status();
        }
        if (plaintext != decrypt_result.ValueOrDie())
          return crypto::tink::util::Status(
              absl::StatusCode::kInternal,
              "Regular Encryption-Decryption failed:"
              "ciphertext differs from plaintext");
      }
      {  // Encryption and decryption with empty context info
        const absl::string_view empty_context_info;
        auto ciphertext =
            hybrid_encrypt->Encrypt(plaintext, empty_context_info).ValueOrDie();
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, empty_context_info);

        if (!decrypt_result.ok()) {
          return decrypt_result.status();
        }
        if (plaintext != decrypt_result.ValueOrDie())
          return crypto::tink::util::Status(
              absl::StatusCode::kInternal,
              "Empty Context Info Encryption-Decryption failed:"
              "ciphertext differs from plaintext");
      }
      {  // Encryption and decryption w/ empty msg & context info
        const absl::string_view empty_plaintext;
        const absl::string_view empty_context_info;
        auto ciphertext =
            hybrid_encrypt->Encrypt(empty_plaintext, empty_context_info)
                .ValueOrDie();
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, empty_context_info);
        if (!decrypt_result.ok()) {
          return decrypt_result.status();
        }
        if (empty_plaintext != decrypt_result.ValueOrDie())
          return crypto::tink::util::Status(
              absl::StatusCode::kInternal,
              "Empty Context Info and Message Encryption-Decryption failed:"
              "ciphertext differs from plaintext");
      }
      {  // Short bad ciphertext
        auto decrypt_result =
            hybrid_decrypt->Decrypt(Random::GetRandomBytes(16), context_info);
        if (decrypt_result.status().code() !=
                absl::StatusCode::kInvalidArgument ||
            !absl::StrContains(decrypt_result.status().error_message(),
                               "ciphertext too short")) {
          return decrypt_result.status();
        }
      }
      {  // Long but still bad ciphertext
        auto decrypt_result =
            hybrid_decrypt->Decrypt(Random::GetRandomBytes(1198), context_info);
        if (decrypt_result.ok()) {
          return crypto::tink::util::Status(absl::StatusCode::kInternal,
                                            "Decrypted random ciphertext");
        }
      }
      {  // Bad context info
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, Random::GetRandomBytes(14));
        if (decrypt_result.ok()) {
          return crypto::tink::util::Status(
              absl::StatusCode::kInternal,
              "Decrypted ciphertext with random context info");
        }
      }
    }
    return util::OkStatus();
  }
};

google::crypto::tink::Cecpq2AeadHkdfPrivateKey CreateValidKey() {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey recipient_key;

  auto cecp2_key_pair = crypto::tink::pqc::GenerateCecpq2Keypair(
                            subtle::EllipticCurveType::CURVE25519)
                            .ValueOrDie();

  recipient_key.set_x25519_private_key(std::string(
      util::SecretDataAsStringView(cecp2_key_pair.x25519_key_pair.priv)));
  recipient_key.set_hrss_private_key_seed(
      std::string(util::SecretDataAsStringView(
          cecp2_key_pair.hrss_key_pair.hrss_private_key_seed)));

  recipient_key.mutable_public_key()->set_x25519_public_key_x(
      cecp2_key_pair.x25519_key_pair.pub_x);
  recipient_key.mutable_public_key()->set_hrss_public_key_marshalled(
      cecp2_key_pair.hrss_key_pair.hrss_public_key_marshaled);

  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_curve_type(google::crypto::tink::EllipticCurveType::CURVE25519);
  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_ec_point_format(google::crypto::tink::EcPointFormat::COMPRESSED);
  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_hkdf_hash_type(google::crypto::tink::HashType::SHA256);

  google::crypto::tink::AesGcmKeyFormat key_format;
  key_format.set_key_size(32);
  std::string dem_key_type = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::AesGcmKey().GetTypeName());
  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_dem_params()
      ->mutable_aead_dem()
      ->set_type_url(dem_key_type);
  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_dem_params()
      ->mutable_aead_dem()
      ->set_value(key_format.SerializeAsString());

  return recipient_key;
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, ValidKey) {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey recipient_key =
      CreateValidKey();
  EXPECT_THAT(Cecpq2AeadHkdfHybridDecrypt::New(recipient_key).status(), IsOk());
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, InvalidKeyNoFieldsSet) {
  EXPECT_THAT(Cecpq2AeadHkdfHybridDecrypt::New(
                  google::crypto::tink::Cecpq2AeadHkdfPrivateKey())
                  .status(),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("missing KEM required fields")));
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, InvalidKeyX25519PrivKeyFieldMissing) {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey recipient_key =
      CreateValidKey();
  recipient_key.set_x25519_private_key("");
  EXPECT_THAT(Cecpq2AeadHkdfHybridDecrypt::New(recipient_key).status(),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("missing KEM required fields")));
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, InvalidKeyX25519PubKeyFieldMissing) {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey recipient_key =
      CreateValidKey();
  recipient_key.mutable_public_key()->set_x25519_public_key_x("");
  EXPECT_THAT(Cecpq2AeadHkdfHybridDecrypt::New(recipient_key).status(),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("missing KEM required fields")));
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, InvalidKeyHrssPrivKeyFieldMissing) {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey recipient_key =
      CreateValidKey();
  recipient_key.set_hrss_private_key_seed("");
  EXPECT_THAT(Cecpq2AeadHkdfHybridDecrypt::New(recipient_key).status(),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("missing KEM required fields")));
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, InvalidKeyHrssPubKeyFieldMissing) {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey recipient_key =
      CreateValidKey();
  recipient_key.mutable_public_key()->set_hrss_public_key_marshalled("");
  EXPECT_THAT(Cecpq2AeadHkdfHybridDecrypt::New(recipient_key).status(),
              StatusIs(util::error::INVALID_ARGUMENT,
                       HasSubstr("missing KEM required fields")));
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, InvalidKeyWrongEcType) {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey recipient_key =
      CreateValidKey();
  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_curve_type(google::crypto::tink::EllipticCurveType::NIST_P256);
  auto result(Cecpq2AeadHkdfHybridDecrypt::New(recipient_key));
  EXPECT_THAT(result.status(),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("Unsupported elliptic curve")));
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, InvalidKeyUnsupportedDem) {
  google::crypto::tink::Cecpq2AeadHkdfPrivateKey recipient_key =
      CreateValidKey();
  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_curve_type(google::crypto::tink::EllipticCurveType::CURVE25519);
  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_kem_params()
      ->set_hkdf_hash_type(google::crypto::tink::HashType::SHA256);
  recipient_key.mutable_public_key()
      ->mutable_params()
      ->mutable_dem_params()
      ->mutable_aead_dem()
      ->set_type_url("some.type.url/that.is.not.supported");
  auto result(Cecpq2AeadHkdfHybridDecrypt::New(recipient_key));
  EXPECT_THAT(result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                        HasSubstr("Unsupported DEM")));
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, AesGcmHybridDecryption) {
  // Register DEM key manager
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true)
                  .ok());

  // Generate and test many keys with various parameters
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    for (uint32_t aes_gcm_key_size : {16, 32}) {
      SCOPED_TRACE(absl::StrCat(key_params.ec_curve, ":",
                                key_params.ec_point_format, ":",
                                key_params.hash_type, ":", aes_gcm_key_size));
      auto cecpq2_key_pair_or_status =
          pqc::GenerateCecpq2Keypair(key_params.ec_curve);
      auto cecpq2_key_pair = std::move(cecpq2_key_pair_or_status.ValueOrDie());
      google::crypto::tink::Cecpq2AeadHkdfPrivateKey cecpq2_key;
      cecpq2_key.set_hrss_private_key_seed(
          std::string(util::SecretDataAsStringView(
              cecpq2_key_pair.hrss_key_pair.hrss_private_key_seed)));
      cecpq2_key.set_x25519_private_key(std::string(
          util::SecretDataAsStringView(cecpq2_key_pair.x25519_key_pair.priv)));
      cecpq2_key.mutable_public_key()->set_hrss_public_key_marshalled(
          cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
      cecpq2_key.mutable_public_key()->set_x25519_public_key_x(
          cecpq2_key_pair.x25519_key_pair.pub_x);
      cecpq2_key.mutable_public_key()
          ->mutable_params()
          ->mutable_kem_params()
          ->set_curve_type(util::Enums::SubtleToProto(key_params.ec_curve));
      cecpq2_key.mutable_public_key()
          ->mutable_params()
          ->mutable_kem_params()
          ->set_ec_point_format(
              util::Enums::SubtleToProto(key_params.ec_point_format));
      cecpq2_key.mutable_public_key()
          ->mutable_params()
          ->mutable_kem_params()
          ->set_hkdf_hash_type(
              util::Enums::SubtleToProto(key_params.hash_type));
      google::crypto::tink::AesGcmKeyFormat key_format;
      key_format.set_key_size(aes_gcm_key_size);
      std::unique_ptr<AesGcmKeyManager> key_manager(new AesGcmKeyManager());
      std::string dem_key_type = key_manager->get_key_type();
      cecpq2_key.mutable_public_key()
          ->mutable_params()
          ->mutable_dem_params()
          ->mutable_aead_dem()
          ->set_type_url(dem_key_type);
      cecpq2_key.mutable_public_key()
          ->mutable_params()
          ->mutable_dem_params()
          ->mutable_aead_dem()
          ->set_value(key_format.SerializeAsString());

      EXPECT_THAT(CheckKeyValidity(cecpq2_key), IsOk());
    }
  }
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, XChaCha20Poly1305HybridDecryption) {
  // Register DEM key manager
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<XChaCha20Poly1305KeyManager>(), true)
                  .ok());

  // Generate and test many keys with various parameters
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    SCOPED_TRACE(absl::StrCat(key_params.ec_curve, ":",
                              key_params.ec_point_format, ":",
                              key_params.hash_type));
    auto cecpq2_key_pair_or_status =
        pqc::GenerateCecpq2Keypair(key_params.ec_curve);
    auto cecpq2_key_pair = std::move(cecpq2_key_pair_or_status.ValueOrDie());
    google::crypto::tink::Cecpq2AeadHkdfPrivateKey cecpq2_key;
    cecpq2_key.set_hrss_private_key_seed(
        std::string(util::SecretDataAsStringView(
            cecpq2_key_pair.hrss_key_pair.hrss_private_key_seed)));
    cecpq2_key.set_x25519_private_key(std::string(
        util::SecretDataAsStringView(cecpq2_key_pair.x25519_key_pair.priv)));
    cecpq2_key.mutable_public_key()->set_hrss_public_key_marshalled(
        cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
    cecpq2_key.mutable_public_key()->set_x25519_public_key_x(
        cecpq2_key_pair.x25519_key_pair.pub_x);
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_kem_params()
        ->set_curve_type(util::Enums::SubtleToProto(key_params.ec_curve));
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_kem_params()
        ->set_ec_point_format(
            util::Enums::SubtleToProto(key_params.ec_point_format));
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_kem_params()
        ->set_hkdf_hash_type(util::Enums::SubtleToProto(key_params.hash_type));

    google::crypto::tink::XChaCha20Poly1305KeyFormat key_format;
    std::unique_ptr<XChaCha20Poly1305KeyManager> key_manager(
        new XChaCha20Poly1305KeyManager());
    std::string dem_key_type = key_manager->get_key_type();
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_dem_params()
        ->mutable_aead_dem()
        ->set_type_url(dem_key_type);
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_dem_params()
        ->mutable_aead_dem()
        ->set_value(key_format.SerializeAsString());

    EXPECT_THAT(CheckKeyValidity(cecpq2_key), IsOk());
  }
}

TEST_F(Cecpq2AeadHkdfHybridDecryptTest, AesSivHybridDecryption) {
  // Register DEM key manager
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesSivKeyManager>(), true)
                  .ok());

  // Generate and test many keys with various parameters
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    auto cecpq2_key_pair_or_status =
        pqc::GenerateCecpq2Keypair(key_params.ec_curve);
    auto cecpq2_key_pair = std::move(cecpq2_key_pair_or_status.ValueOrDie());
    google::crypto::tink::Cecpq2AeadHkdfPrivateKey cecpq2_key;
    cecpq2_key.set_hrss_private_key_seed(
        std::string(util::SecretDataAsStringView(
            cecpq2_key_pair.hrss_key_pair.hrss_private_key_seed)));
    cecpq2_key.set_x25519_private_key(std::string(
        util::SecretDataAsStringView(cecpq2_key_pair.x25519_key_pair.priv)));
    cecpq2_key.mutable_public_key()->set_hrss_public_key_marshalled(
        cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
    cecpq2_key.mutable_public_key()->set_x25519_public_key_x(
        cecpq2_key_pair.x25519_key_pair.pub_x);
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_kem_params()
        ->set_curve_type(util::Enums::SubtleToProto(key_params.ec_curve));
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_kem_params()
        ->set_ec_point_format(
            util::Enums::SubtleToProto(key_params.ec_point_format));
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_kem_params()
        ->set_hkdf_hash_type(util::Enums::SubtleToProto(key_params.hash_type));

    google::crypto::tink::AesSivKeyFormat key_format;
    key_format.set_key_size(64);
    std::unique_ptr<AesSivKeyManager> key_manager(new AesSivKeyManager());
    std::string dem_key_type = key_manager->get_key_type();
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_dem_params()
        ->mutable_aead_dem()
        ->set_type_url(dem_key_type);
    cecpq2_key.mutable_public_key()
        ->mutable_params()
        ->mutable_dem_params()
        ->mutable_aead_dem()
        ->set_value(key_format.SerializeAsString());

    EXPECT_THAT(CheckKeyValidity(cecpq2_key), IsOk());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
