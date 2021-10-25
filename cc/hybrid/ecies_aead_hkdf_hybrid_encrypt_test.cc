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

#include "tink/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"

#include "absl/memory/memory.h"
#include "tink/hybrid_encrypt.h"
#include "tink/registry.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "gtest/gtest.h"

using google::crypto::tink::EciesAeadHkdfPublicKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;


namespace crypto {
namespace tink {
namespace {

class EciesAeadHkdfHybridEncryptTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(EciesAeadHkdfHybridEncryptTest, testInvalidKeys) {
  {  // No fields set.
    EciesAeadHkdfPublicKey recipient_key;
    auto result = EciesAeadHkdfHybridEncrypt::New(recipient_key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "missing required fields",
                        std::string(result.status().message()));
  }

  {  // Only some fields set.
    EciesAeadHkdfPublicKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.set_x("some x bytes");
    recipient_key.set_y("some y bytes");
    auto result(EciesAeadHkdfHybridEncrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "missing required fields",
                        std::string(result.status().message()));
  }

  {  // Wrong EC type.
    EciesAeadHkdfPublicKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.set_x("some x bytes");
    recipient_key.set_y("some y bytes");
    recipient_key.mutable_params();
    auto result(EciesAeadHkdfHybridEncrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kUnimplemented, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unsupported elliptic curve",
                        std::string(result.status().message()));
  }

  {  // Unsupported DEM key type.
    EllipticCurveType curve = EllipticCurveType::NIST_P256;
    auto test_key = subtle::SubtleUtilBoringSSL::GetNewEcKey(
        util::Enums::ProtoToSubtle(curve)).ValueOrDie();
    EciesAeadHkdfPublicKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.set_x(test_key.pub_x);
    recipient_key.set_y(test_key.pub_y);
    auto params = recipient_key.mutable_params();
    params->mutable_kem_params()->set_curve_type(curve);
    params->mutable_kem_params()->set_hkdf_hash_type(HashType::SHA256);
    auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
    aead_dem->set_type_url("some.type.url/that.is.not.supported");
    auto result(EciesAeadHkdfHybridEncrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unsupported DEM",
                        std::string(result.status().message()));
  }
}

TEST_F(EciesAeadHkdfHybridEncryptTest, testBasic) {
  // Prepare an ECIES key.
  auto ecies_key = test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256,
      EcPointFormat::UNCOMPRESSED,
      HashType::SHA256,
      32);

  // Try to get a HybridEncrypt primitive without DEM key manager.
  auto bad_result(EciesAeadHkdfHybridEncrypt::New(ecies_key.public_key()));
  EXPECT_FALSE(bad_result.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, bad_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "No manager for DEM",
                      std::string(bad_result.status().message()));

  // Register DEM key manager.
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true)
                  .ok());
  std::string dem_key_type = AesGcmKeyManager().get_key_type();

  // Generate and test many keys with various parameters.
  std::string plaintext = "some plaintext";
  std::string context_info = "some context info";
  for (auto curve : {EllipticCurveType::NIST_P256, EllipticCurveType::NIST_P384,
                     EllipticCurveType::NIST_P521}) {
    for (auto ec_point_format :
        {EcPointFormat::UNCOMPRESSED, EcPointFormat::COMPRESSED}) {
      for (auto hash_type : {HashType::SHA256, HashType::SHA512}) {
        for (uint32_t aes_gcm_key_size : {16, 32}) {
          ecies_key = test::GetEciesAesGcmHkdfTestKey(
              curve, ec_point_format, hash_type, aes_gcm_key_size);
          auto result(EciesAeadHkdfHybridEncrypt::New(ecies_key.public_key()));
          ASSERT_TRUE(result.ok()) << result.status()
                                   << ecies_key.SerializeAsString();
          std::unique_ptr<HybridEncrypt> hybrid_encrypt(
              std::move(result.ValueOrDie()));

          // Use the primitive.
          auto encrypt_result =
              hybrid_encrypt->Encrypt(plaintext, context_info);
          EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
        }
      }
    }
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
