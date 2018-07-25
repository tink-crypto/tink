// Copyright 2017 Google Inc.
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

#include "tink/subtle/ecdsa_sign_boringssl.h"

#include <string>

#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class EcdsaSignBoringSslTest : public ::testing::Test {
};

TEST_F(EcdsaSignBoringSslTest, testBasicSigning) {
  auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(
      EllipticCurveType::NIST_P256).ValueOrDie();
  auto signer_result = EcdsaSignBoringSsl::New(ec_key, HashType::SHA256);
  ASSERT_TRUE(signer_result.ok()) << signer_result.status();
  auto signer = std::move(signer_result.ValueOrDie());

  auto verifier_result = EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.ValueOrDie());

  std::string message = "some data to be signed";
  std::string signature = signer->Sign(message).ValueOrDie();
  EXPECT_NE(signature, message);
  auto status = verifier->Verify(signature, message);
  EXPECT_TRUE(status.ok()) << status;

  status = verifier->Verify("some bad signature", message);
  EXPECT_FALSE(status.ok());

  status = verifier->Verify(signature, "some bad message");
  EXPECT_FALSE(status.ok());

  // Message is a null string_view.
  const absl::string_view empty_message;
  signature = signer->Sign(empty_message).ValueOrDie();
  EXPECT_NE(signature, empty_message);
  status = verifier->Verify(signature, empty_message);
  EXPECT_TRUE(status.ok()) << status;
}

TEST_F(EcdsaSignBoringSslTest, testNewErrors) {
  auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256)
                    .ValueOrDie();
  auto signer_result = EcdsaSignBoringSsl::New(ec_key, HashType::SHA1);
  EXPECT_FALSE(signer_result.ok()) << signer_result.status();
}

// TODO(bleichen): add Wycheproof tests.

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

int main(int ac, char *av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
