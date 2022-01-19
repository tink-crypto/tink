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

#include "tink/hybrid/internal/hpke_key_manager_util.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

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

TEST(HpkeKeyManagerUtilTest, ValidateValidParamsSucceeds) {
  ASSERT_THAT(ValidateParams(CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                              HpkeKdf::HKDF_SHA256,
                                              HpkeAead::AES_256_GCM)),
              IsOk());
}

TEST(HpkeKeyManagerUtilTest, ValidateInvalidParamsFails) {
  ASSERT_THAT(
      ValidateParams(CreateHpkeParams(
          HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256, HpkeAead::AES_256_GCM)),
      StatusIs(absl::StatusCode::kInvalidArgument));

  ASSERT_THAT(ValidateParams(CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                              HpkeKdf::KDF_UNKNOWN,
                                              HpkeAead::AES_256_GCM)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASSERT_THAT(ValidateParams(CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                              HpkeKdf::HKDF_SHA256,
                                              HpkeAead::AEAD_UNKNOWN)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeKeyManagerUtilTest, ValidateValidKeyAndVersionSucceeds) {
  HpkePublicKey key = CreateHpkePublicKey(
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_256_GCM),
      "rawkeybytes");

  ASSERT_THAT(ValidateKeyAndVersion(key, /*max_key_version=*/1), IsOk());
}

TEST(HpkeKeyManagerUtilTest, ValidateTooHighKeyVersionFails) {
  HpkePublicKey key = CreateHpkePublicKey(
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_256_GCM),
      "rawkeybytes");
  key.set_version(1);

  ASSERT_THAT(ValidateKeyAndVersion(key, /*max_key_version=*/0),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeKeyManagerUtilTest, ValidateMissingKeyParamsFails) {
  HpkePublicKey key = CreateHpkePublicKey(
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_256_GCM),
      "rawkeybytes");
  key.clear_params();

  ASSERT_THAT(ValidateKeyAndVersion(key, /*max_key_version=*/1),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
