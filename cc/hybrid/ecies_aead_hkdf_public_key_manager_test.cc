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

#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid_encrypt.h"
#include "tink/registry.h"
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
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::EciesAeadHkdfKeyFormat;
using ::google::crypto::tink::EciesAeadHkdfParams;
using ::google::crypto::tink::EciesAeadHkdfPublicKey;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;

TEST(EciesAeadHkdfPublicKeyManagerTest, Basics) {
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().get_version(), Eq(0));
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(
      EciesAeadHkdfPublicKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey"));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(
      EciesAeadHkdfPublicKeyManager().ValidateKey(EciesAeadHkdfPublicKey()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

EciesAeadHkdfPublicKey CreatePublicKey() {
  EciesAeadHkdfKeyFormat key_format;
  key_format.mutable_params()->set_ec_point_format(EcPointFormat::UNCOMPRESSED);
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  *(dem_params->mutable_aead_dem()) = AeadKeyTemplates::Aes128Gcm();
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  kem_params->set_curve_type(EllipticCurveType::NIST_P256);
  kem_params->set_hkdf_hash_type(HashType::SHA256);
  kem_params->set_hkdf_salt("");
  auto private_key_manager = EciesAeadHkdfPrivateKeyManager();
  return private_key_manager
      .GetPublicKey(private_key_manager.CreateKey(key_format).ValueOrDie())
      .value();
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateParams) {
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(
                  CreatePublicKey().params()),
              IsOk());
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateKeyNoPoint) {
  EciesAeadHkdfParams params = CreatePublicKey().params();
  params.set_ec_point_format(EcPointFormat::UNKNOWN_FORMAT);
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateKeyNoDem) {
  EciesAeadHkdfParams params = CreatePublicKey().params();
  params.mutable_dem_params()->clear_aead_dem();
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateKeyNoKemCurve) {
  EciesAeadHkdfParams params = CreatePublicKey().params();
  params.mutable_kem_params()->set_curve_type(EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateKeyNoKemHash) {
  EciesAeadHkdfParams params = CreatePublicKey().params();
  params.mutable_kem_params()->set_hkdf_hash_type(HashType::UNKNOWN_HASH);
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateGeneratedKey) {
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateKey(CreatePublicKey()),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
