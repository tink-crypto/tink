// Copyright 2017 Google LLC
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

#include "tink/hybrid/ecies_aead_hkdf_hybrid_decrypt.h"

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"
#include "tink/hybrid_decrypt.h"
#include "tink/registry.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"

using crypto::tink::subtle::Random;
using google::crypto::tink::EciesAeadHkdfPrivateKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;


namespace crypto {
namespace tink {
namespace {

class EciesAeadHkdfHybridDecryptTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }

  struct CommonHybridKeyParams {
    EllipticCurveType ec_curve;
    EcPointFormat ec_point_format;
    HashType hash_type;
  };

  std::vector<CommonHybridKeyParams> GetCommonHybridKeyParamsList() {
    std::vector<CommonHybridKeyParams> params_list;
    for (auto ec_curve :
         {EllipticCurveType::NIST_P256, EllipticCurveType::NIST_P384,
          EllipticCurveType::NIST_P521, EllipticCurveType::CURVE25519}) {
      for (auto ec_point_format :
           {EcPointFormat::UNCOMPRESSED, EcPointFormat::COMPRESSED}) {
        if (ec_curve == EllipticCurveType::CURVE25519 &&
            ec_point_format == EcPointFormat::UNCOMPRESSED) {
          continue;
        }
        for (auto hash_type : {HashType::SHA256, HashType::SHA512}) {
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

  void TestValidKey(const EciesAeadHkdfPrivateKey& ecies_key) {
    auto result(EciesAeadHkdfHybridDecrypt::New(ecies_key));
    ASSERT_TRUE(result.ok()) << result.status() << ecies_key.DebugString();
    std::unique_ptr<HybridDecrypt> hybrid_decrypt(
        std::move(result.ValueOrDie()));

    std::unique_ptr<HybridEncrypt> hybrid_encrypt(std::move(
        EciesAeadHkdfHybridEncrypt::New(ecies_key.public_key()).ValueOrDie()));

    std::string context_info = "some context info";
    for (uint32_t plaintext_size : {0, 1, 10, 100, 1000}) {
      // Use the primitive.
      std::string plaintext = Random::GetRandomBytes(plaintext_size);
      auto ciphertext =
          hybrid_encrypt->Encrypt(plaintext, context_info).ValueOrDie();
      {  // Regular decryption.
        auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
        EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
        EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
      }
      {  // Encryption and decryption with empty context info.
        const absl::string_view empty_context_info;
        auto ciphertext =
            hybrid_encrypt->Encrypt(plaintext, empty_context_info).ValueOrDie();
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, empty_context_info);
        ASSERT_TRUE(decrypt_result.ok()) << decrypt_result.status();
        EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
      }
      {  // Encryption and decryption w/ empty msg & context info.
        const absl::string_view empty_plaintext;
        const absl::string_view empty_context_info;
        auto ciphertext =
            hybrid_encrypt->Encrypt(empty_plaintext, empty_context_info)
                .ValueOrDie();
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, empty_context_info);
        ASSERT_TRUE(decrypt_result.ok()) << decrypt_result.status();
        EXPECT_EQ(empty_plaintext, decrypt_result.ValueOrDie());
      }
      {  // Short bad ciphertext.
        auto decrypt_result =
            hybrid_decrypt->Decrypt(Random::GetRandomBytes(16), context_info);
        EXPECT_FALSE(decrypt_result.ok());
        EXPECT_EQ(util::error::INVALID_ARGUMENT,
                  decrypt_result.status().error_code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "ciphertext too short",
                            decrypt_result.status().error_message());
      }
      {  // Long but still bad ciphertext.
        auto decrypt_result =
            hybrid_decrypt->Decrypt(Random::GetRandomBytes(142), context_info);
        EXPECT_FALSE(decrypt_result.ok());
        // TODO(przydatek): add more checks while avoiding flakiness.
      }
      {  // Bad context info
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, Random::GetRandomBytes(14));
        EXPECT_FALSE(decrypt_result.ok());
      }
    }
  }
};

TEST_F(EciesAeadHkdfHybridDecryptTest, testInvalidKeys) {
  {  // No fields set.
    EciesAeadHkdfPrivateKey recipient_key;
    auto result = EciesAeadHkdfHybridDecrypt::New(recipient_key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "missing required fields",
                        result.status().error_message());
  }

  {  // Only some fields set.
    EciesAeadHkdfPrivateKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.mutable_public_key()->set_x("some x bytes");
    recipient_key.mutable_public_key()->set_y("some y bytes");
    auto result(EciesAeadHkdfHybridDecrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "missing required fields",
                        result.status().error_message());
  }

  {  // Wrong EC type.
    EciesAeadHkdfPrivateKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.set_key_value("some key value bytes");
    recipient_key.mutable_public_key()->set_x("some x bytes");
    recipient_key.mutable_public_key()->set_y("some y bytes");
    recipient_key.mutable_public_key()->mutable_params();
    auto result(EciesAeadHkdfHybridDecrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unsupported elliptic curve",
                        result.status().error_message());
  }

  {  // Unsupported DEM key type.
    EllipticCurveType curve = EllipticCurveType::NIST_P256;
    auto test_key = subtle::SubtleUtilBoringSSL::GetNewEcKey(
        util::Enums::ProtoToSubtle(curve)).ValueOrDie();
    EciesAeadHkdfPrivateKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.set_key_value("some key value bytes");
    recipient_key.mutable_public_key()->set_x(test_key.pub_x);
    recipient_key.mutable_public_key()->set_y(test_key.pub_y);
    auto params = recipient_key.mutable_public_key()->mutable_params();
    params->mutable_kem_params()->set_curve_type(curve);
    params->mutable_kem_params()->set_hkdf_hash_type(HashType::SHA256);
    auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
    aead_dem->set_type_url("some.type.url/that.is.not.supported");
    auto result(EciesAeadHkdfHybridDecrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unsupported DEM",
                        result.status().error_message());
  }
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testGettingHybridEncryptWithoutManager) {
  // Prepare an ECIES key.
  Registry::Reset();
  auto ecies_key = test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256,
      EcPointFormat::UNCOMPRESSED,
      HashType::SHA256,
      32);

  // Try to get a HybridEncrypt primitive without DEM key manager.
  auto bad_result(EciesAeadHkdfHybridDecrypt::New(ecies_key));
  EXPECT_FALSE(bad_result.ok());
  EXPECT_EQ(util::error::FAILED_PRECONDITION, bad_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "No manager for DEM",
                      bad_result.status().error_message());
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testAesGcmHybridDecryption) {
  // Register DEM key manager.
  std::string dem_key_type = AesGcmKeyManager().get_key_type();
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true)
                  .ok());

  int i = 0;
  // Generate and test many keys with various parameters.
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    for (uint32_t aes_gcm_key_size : {16, 32}) {
      ++i;
      auto ecies_key = test::GetEciesAesGcmHkdfTestKey(
          key_params.ec_curve, key_params.ec_point_format, key_params.hash_type,
          aes_gcm_key_size);
      TestValidKey(ecies_key);
    }
  }
  EXPECT_EQ(i, 32 - 4);
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testAesCtrAeadHybridDecryption) {
  // Register DEM key manager.
  std::string dem_key_type = AesCtrHmacAeadKeyManager().get_key_type();
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesCtrHmacAeadKeyManager>(), true)
                  .ok());

  uint32_t aes_ctr_iv_size = 16;
  // Generate and test many keys with various parameters.
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    for (uint32_t aes_ctr_key_size : {16, 32}) {
      for (auto hmac_hash_type : {HashType::SHA256, HashType::SHA512}) {
        for (uint32_t hmac_tag_size : {16, 32}) {
          for (uint32_t hmac_key_size : {16, 32}) {
            auto ecies_key = test::GetEciesAesCtrHmacHkdfTestKey(
                key_params.ec_curve, key_params.ec_point_format,
                key_params.hash_type, aes_ctr_key_size, aes_ctr_iv_size,
                hmac_hash_type, hmac_tag_size, hmac_key_size);
            TestValidKey(ecies_key);
          }
        }
      }
    }
  }
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testXChaCha20Poly1305HybridDecryption) {
  // Register DEM key manager.
  std::string dem_key_type = XChaCha20Poly1305KeyManager().get_key_type();
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<XChaCha20Poly1305KeyManager>(), true)
                  .ok());

  // Generate and test many keys with various parameters.
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    auto ecies_key = test::GetEciesXChaCha20Poly1305HkdfTestKey(
        key_params.ec_curve, key_params.ec_point_format, key_params.hash_type);
    TestValidKey(ecies_key);
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
