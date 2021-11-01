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

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/config/tink_fips.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ec_util.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::StatusIs;

class EcdsaSignBoringSslTest : public ::testing::Test {
};

TEST_F(EcdsaSignBoringSslTest, testBasicSigning) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      EcdsaSignatureEncoding::DER, EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256)
                      .ValueOrDie();
    auto signer_result =
        EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.ValueOrDie());

    auto verifier_result =
        EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256, encoding);
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
}

TEST_F(EcdsaSignBoringSslTest, testEncodingsMismatch) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      EcdsaSignatureEncoding::DER, EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256)
                      .ValueOrDie();
    auto signer_result =
        EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.ValueOrDie());

    auto verifier_result =
        EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256,
                                  encoding == EcdsaSignatureEncoding::DER
                                      ? EcdsaSignatureEncoding::IEEE_P1363
                                      : EcdsaSignatureEncoding::DER);
    ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
    auto verifier = std::move(verifier_result.ValueOrDie());

    std::string message = "some data to be signed";
    std::string signature = signer->Sign(message).ValueOrDie();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_FALSE(status.ok()) << status;
  }
}

TEST_F(EcdsaSignBoringSslTest, testSignatureSizesWithIEEE_P1364Encoding) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  EllipticCurveType curves[3] = {EllipticCurveType::NIST_P256,
                                 EllipticCurveType::NIST_P384,
                                 EllipticCurveType::NIST_P521};
  for (EllipticCurveType curve : curves) {
    auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(curve).ValueOrDie();
    auto signer_result = EcdsaSignBoringSsl::New(
        ec_key, HashType::SHA256, EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.ValueOrDie());

    auto verifier_result = EcdsaVerifyBoringSsl::New(
        ec_key, HashType::SHA256, EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
    auto verifier = std::move(verifier_result.ValueOrDie());

    std::string message = "some data to be signed";
    std::string signature = signer->Sign(message).ValueOrDie();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_TRUE(status.ok()) << status;

    // Check signature size.
    auto field_size_in_bytes = EcUtil::FieldSizeInBytes(curve);
    EXPECT_EQ(2 * field_size_in_bytes, signature.size());
  }
}

TEST_F(EcdsaSignBoringSslTest, testNewErrors) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256)
                    .ValueOrDie();
  auto signer_result = EcdsaSignBoringSsl::New(ec_key, HashType::SHA1,
                                               EcdsaSignatureEncoding::DER);
  EXPECT_FALSE(signer_result.ok()) << signer_result.status();
}

// TODO(bleichen): add Wycheproof tests.

// FIPS-only mode test
TEST_F(EcdsaSignBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256)
                    .ValueOrDie();
  EXPECT_THAT(EcdsaSignBoringSsl::New(ec_key, HashType::SHA256,
                                      EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));

  ec_key = SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P384)
                    .ValueOrDie();
  EXPECT_THAT(EcdsaSignBoringSsl::New(ec_key, HashType::SHA256,
                                      EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));

  ec_key = SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P521)
                    .ValueOrDie();
  EXPECT_THAT(EcdsaSignBoringSsl::New(ec_key, HashType::SHA256,
                                      EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
