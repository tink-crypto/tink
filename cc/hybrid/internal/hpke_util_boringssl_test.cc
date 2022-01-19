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

#include "tink/hybrid/internal/hpke_util_boringssl.h"

#include <string>

#include "gtest/gtest.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using ::testing::Eq;
using ::testing::Not;

TEST(HpkeUtilBoringSslTest, ValidParams) {
  HpkeParams params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_256_GCM);

  util::StatusOr<const EVP_HPKE_KEM *> kem = KemParam(params);
  ASSERT_THAT(kem.status(), IsOk());
  EXPECT_THAT(EVP_HPKE_KEM_id(*kem),
              Eq(EVP_HPKE_DHKEM_X25519_HKDF_SHA256));

  util::StatusOr<const EVP_HPKE_KDF *> kdf = KdfParam(params);
  ASSERT_THAT(kdf.status(), IsOk());
  EXPECT_THAT(EVP_HPKE_KDF_id(*kdf), Eq(EVP_HPKE_HKDF_SHA256));

  util::StatusOr<const EVP_HPKE_AEAD *> aead = AeadParam(params);
  ASSERT_THAT(aead.status(), IsOk());
  EXPECT_THAT(EVP_HPKE_AEAD_id(*aead), Eq(EVP_HPKE_AES_256_GCM));
}

TEST(HpkeUtilBoringSslTest, UnknownKemParam) {
  HpkeParams params = CreateHpkeParams(
      HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256, HpkeAead::AES_256_GCM);
  EXPECT_THAT(KemParam(params).status(), Not(IsOk()));
  EXPECT_THAT(KdfParam(params).status(), IsOk());
  EXPECT_THAT(AeadParam(params).status(), IsOk());
}

TEST(HpkeUtilBoringSslTest, UnknownKdfParam) {
  HpkeParams params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::KDF_UNKNOWN,
                       HpkeAead::AES_256_GCM);
  EXPECT_THAT(KemParam(params).status(), IsOk());
  EXPECT_THAT(KdfParam(params).status(), Not(IsOk()));
  EXPECT_THAT(AeadParam(params).status(), IsOk());
}

TEST(HpkeUtilBoringSslTest, UnknownAeadParam) {
  HpkeParams params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AEAD_UNKNOWN);
  EXPECT_THAT(KemParam(params).status(), IsOk());
  EXPECT_THAT(KdfParam(params).status(), IsOk());
  EXPECT_THAT(AeadParam(params).status(), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
