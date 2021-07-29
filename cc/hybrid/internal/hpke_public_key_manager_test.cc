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

#include "tink/hybrid/internal/hpke_public_key_manager.h"

#include "gtest/gtest.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::CreateHpkeParams;
using ::crypto::tink::internal::CreateHpkePublicKey;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkePublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;

TEST(HpkePublicKeyManagerTest, BasicAccessors) {
  EXPECT_THAT(HpkePublicKeyManager().get_version(), Eq(0));
  EXPECT_THAT(HpkePublicKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(HpkePublicKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.HpkePublicKey"));
}

TEST(HpkePublicKeyManagerTest, ValidateEmptyKeyFails) {
  EXPECT_THAT(HpkePublicKeyManager().ValidateKey(HpkePublicKey()),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(HpkePublicKeyManagerTest, ValidateKeySucceeds) {
  EXPECT_THAT(HpkePublicKeyManager().ValidateKey(CreateHpkePublicKey(
                  CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                   HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
                  /*raw_key_bytes=*/"")),
              IsOk());
}

TEST(HpkePublicKeyManagerTest, ValidateKeyWithInvalidKemFails) {
  EXPECT_THAT(HpkePublicKeyManager().ValidateKey(CreateHpkePublicKey(
                  CreateHpkeParams(HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256,
                                   HpkeAead::AES_128_GCM),
                  /*raw_key_bytes=*/"")),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(HpkePublicKeyManagerTest, ValidateKeyWithInvalidKdfFails) {
  EXPECT_THAT(HpkePublicKeyManager().ValidateKey(CreateHpkePublicKey(
                  CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                   HpkeKdf::KDF_UNKNOWN, HpkeAead::AES_128_GCM),
                  /*raw_key_bytes=*/"")),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(HpkePublicKeyManagerTest, ValidateKeyWithInvalidAeadFails) {
  EXPECT_THAT(
      HpkePublicKeyManager().ValidateKey(CreateHpkePublicKey(
          CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                           HpkeKdf::HKDF_SHA256, HpkeAead::AEAD_UNKNOWN),
          /*raw_key_bytes=*/"")),
      StatusIs(util::error::INVALID_ARGUMENT));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
