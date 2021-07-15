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

#include "tink/hybrid/internal/hpke_key_boringssl.h"

#include <string>

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_test_util.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;

TEST(HpkeKeyBoringSslTest, CreateValidHpkeKey) {
  HpkeParams hpke_params =
      CreateHpkeParams(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                       HpkeAead::AES_128_GCM);
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<std::unique_ptr<HpkeKeyBoringSsl>> hpke_key =
      HpkeKeyBoringSsl::New(hpke_params.kem(), params.recipient_private_key);
  ASSERT_THAT(hpke_key.status(), IsOk());
}

TEST(HpkeKeyBoringSslTest, BadKemFails) {
  HpkeTestParams params = DefaultHpkeTestParams();
  util::StatusOr<std::unique_ptr<HpkeKeyBoringSsl>> result =
      HpkeKeyBoringSsl::New(HpkeKem::KEM_UNKNOWN,
                            params.recipient_private_key);
  ASSERT_THAT(result.status(), StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(HpkeKeyBoringSslTest, ZeroLengthPrivateKeyFails) {
  util::StatusOr<std::unique_ptr<HpkeKeyBoringSsl>> result =
      HpkeKeyBoringSsl::New(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                            /*recipient_private_key=*/"");
  ASSERT_THAT(result.status(), StatusIs(util::error::UNKNOWN));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
