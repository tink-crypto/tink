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

#include "experimental/pqcrypto/cecpq2/util/test_util.h"

#include "gtest/gtest.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/hybrid_encrypt.h"
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
namespace {

using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;

struct CommonHybridKeyParams {
  EllipticCurveType ec_curve;
  EcPointFormat ec_point_format;
  HashType hash_type;
};

std::vector<CommonHybridKeyParams> GetCommonHybridKeyParamsList() {
  std::vector<CommonHybridKeyParams> params_list;
  for (auto ec_curve : {EllipticCurveType::CURVE25519}) {
    for (auto ec_point_format : {EcPointFormat::COMPRESSED}) {
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

TEST(TestUtilTest, GetCecpq2AeadHkdfTestKeyBasics) {
  auto curve_type = EllipticCurveType::CURVE25519;
  auto ec_point_format = EcPointFormat::COMPRESSED;
  auto hkdf_hash_type = HashType::SHA384;

  auto cecpq2_key = test::GetCecpq2AeadHkdfTestKey(curve_type, ec_point_format,
                                                   hkdf_hash_type);

  auto params = cecpq2_key.mutable_public_key()->mutable_params();

  EXPECT_EQ(params->mutable_kem_params()->curve_type(), curve_type);
  EXPECT_EQ(params->mutable_kem_params()->ec_point_format(), ec_point_format);
  EXPECT_EQ(params->mutable_kem_params()->hkdf_hash_type(), hkdf_hash_type);
}

TEST(TestUtilTest, GetCecpq2AesGcmHkdfTestKeyBasics) {
  auto curve_type = EllipticCurveType::CURVE25519;
  auto ec_point_format = EcPointFormat::COMPRESSED;
  auto hkdf_hash_type = HashType::SHA384;
  auto aes_gcm_key_size = 32;

  auto cecpq2_key = test::GetCecpq2AesGcmHkdfTestKey(
      curve_type, ec_point_format, hkdf_hash_type, aes_gcm_key_size);

  auto params = cecpq2_key.mutable_public_key()->mutable_params();

  EXPECT_EQ(params->mutable_kem_params()->curve_type(), curve_type);
  EXPECT_EQ(params->mutable_kem_params()->ec_point_format(), ec_point_format);
  EXPECT_EQ(params->mutable_kem_params()->hkdf_hash_type(), hkdf_hash_type);
}

TEST(TestUtilTest, GetCecpq2AesCtrHmacHkdfTestKeyBasics) {
  auto curve_type = EllipticCurveType::CURVE25519;
  auto ec_point_format = EcPointFormat::COMPRESSED;
  auto hmac_hash_type = HashType::SHA384;

  uint32_t aes_ctr_iv_size = 16;
  // Generate and test many keys with various parameters
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    for (uint32_t aes_ctr_key_size : {16, 32}) {
      for (uint32_t hmac_tag_size : {16, 32}) {
        for (uint32_t hmac_key_size : {16, 32}) {
          auto cecpq2_key = test::GetCecpq2AesCtrHmacHkdfTestKey(
              key_params.ec_curve, key_params.ec_point_format,
              key_params.hash_type, aes_ctr_key_size, aes_ctr_iv_size,
              hmac_hash_type, hmac_tag_size, hmac_key_size);
          auto params = cecpq2_key.mutable_public_key()->mutable_params();
          EXPECT_EQ(params->mutable_kem_params()->curve_type(), curve_type);
          EXPECT_EQ(params->mutable_kem_params()->ec_point_format(),
                    ec_point_format);
        }
      }
    }
  }
}

TEST(TestUtilTest, GetCecpq2XChaCha20Poly1305HkdfTestKeyBasics) {
  auto curve_type = EllipticCurveType::CURVE25519;
  auto ec_point_format = EcPointFormat::COMPRESSED;
  auto hkdf_hash_type = HashType::SHA384;

  auto cecpq2_key = test::GetCecpq2XChaCha20Poly1305HkdfTestKey(
      curve_type, ec_point_format, hkdf_hash_type);

  auto params = cecpq2_key.mutable_public_key()->mutable_params();

  EXPECT_EQ(params->mutable_kem_params()->curve_type(), curve_type);
  EXPECT_EQ(params->mutable_kem_params()->ec_point_format(), ec_point_format);
  EXPECT_EQ(params->mutable_kem_params()->hkdf_hash_type(), hkdf_hash_type);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
