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

#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_public_key_manager.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_private_key_manager.h"
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

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::Cecpq2AeadHkdfKeyFormat;
using ::google::crypto::tink::Cecpq2AeadHkdfParams;
using ::google::crypto::tink::Cecpq2AeadHkdfPublicKey;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, Basics) {
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().get_version(), Eq(0));
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(
      Cecpq2AeadHkdfPublicKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPublicKey"));
}

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(
      Cecpq2AeadHkdfPublicKeyManager().ValidateKey(Cecpq2AeadHkdfPublicKey()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

Cecpq2AeadHkdfPublicKey CreatePublicKey() {
  Cecpq2AeadHkdfKeyFormat key_format;
  key_format.mutable_params()->mutable_kem_params()->set_ec_point_format(
      EcPointFormat::UNCOMPRESSED);
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  *(dem_params->mutable_aead_dem()) = AeadKeyTemplates::Aes128Gcm();
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  kem_params->set_curve_type(EllipticCurveType::CURVE25519);
  kem_params->set_hkdf_hash_type(HashType::SHA256);
  kem_params->set_hkdf_salt("");
  auto private_key_manager = Cecpq2AeadHkdfPrivateKeyManager();
  return private_key_manager
      .GetPublicKey(private_key_manager.CreateKey(key_format).value())
      .value();
}

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, ValidateParams) {
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().ValidateParams(
                  CreatePublicKey().params()),
              IsOk());
}

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, ValidateKeyNoPoint) {
  Cecpq2AeadHkdfParams params = CreatePublicKey().params();
  params.mutable_kem_params()->set_ec_point_format(
      EcPointFormat::UNKNOWN_FORMAT);
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, ValidateKeyNoDem) {
  Cecpq2AeadHkdfParams params = CreatePublicKey().params();
  params.mutable_dem_params()->clear_aead_dem();
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, ValidateKeyNoKemCurve) {
  Cecpq2AeadHkdfParams params = CreatePublicKey().params();
  params.mutable_kem_params()->set_curve_type(EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, ValidateKeyNoKemHash) {
  Cecpq2AeadHkdfParams params = CreatePublicKey().params();
  params.mutable_kem_params()->set_hkdf_hash_type(HashType::UNKNOWN_HASH);
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, ValidateGeneratedKey) {
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().ValidateKey(CreatePublicKey()),
              IsOk());
}

TEST(Cecpq2AeadHkdfPublicKeyManagerTest, ValidatePublicKeyVersion) {
  Cecpq2AeadHkdfPublicKey pk = CreatePublicKey();
  pk.set_version(1);
  EXPECT_THAT(Cecpq2AeadHkdfPublicKeyManager().ValidateKey(pk), Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
