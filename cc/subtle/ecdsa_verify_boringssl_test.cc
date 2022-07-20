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

#include "tink/subtle/ecdsa_verify_boringssl.h"

#include <iostream>
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "include/rapidjson/document.h"
#include "tink/config/tink_fips.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::StatusIs;

class EcdsaVerifyBoringSslTest : public ::testing::Test {};

TEST_F(EcdsaVerifyBoringSslTest, BasicSigning) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      EcdsaSignatureEncoding::DER, EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    auto ec_key_result =
        SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256);
    ASSERT_TRUE(ec_key_result.ok()) << ec_key_result.status();
    auto ec_key = std::move(ec_key_result.value());

    auto signer_result =
        EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.value());

    auto verifier_result =
        EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
    auto verifier = std::move(verifier_result.value());

    std::string message = "some data to be signed";
    auto sign_result = signer->Sign(message);
    ASSERT_TRUE(sign_result.ok()) << sign_result.status();
    std::string signature = sign_result.value();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_TRUE(status.ok()) << status;

    status = verifier->Verify(signature + "some trailing data", message);
    EXPECT_FALSE(status.ok()) << status;

    status = verifier->Verify("some bad signature", message);
    EXPECT_FALSE(status.ok());

    status = verifier->Verify(signature, "some bad message");
    EXPECT_FALSE(status.ok());
  }
}

TEST_F(EcdsaVerifyBoringSslTest, EncodingsMismatch) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      EcdsaSignatureEncoding::DER, EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    auto ec_key_result =
        SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256);
    ASSERT_TRUE(ec_key_result.ok()) << ec_key_result.status();
    auto ec_key = std::move(ec_key_result.value());

    auto signer_result =
        EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.value());

    auto verifier_result =
        EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256,
                                  encoding == EcdsaSignatureEncoding::DER
                                      ? EcdsaSignatureEncoding::IEEE_P1363
                                      : EcdsaSignatureEncoding::DER);
    ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
    auto verifier = std::move(verifier_result.value());

    std::string message = "some data to be signed";
    auto sign_result = signer->Sign(message);
    ASSERT_TRUE(sign_result.ok()) << sign_result.status();
    std::string signature = sign_result.value();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_FALSE(status.ok()) << status;
  }
}

TEST_F(EcdsaVerifyBoringSslTest, NewErrors) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  auto ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256).value();
  auto verifier_result = EcdsaVerifyBoringSsl::New(
      ec_key, HashType::SHA1, EcdsaSignatureEncoding::IEEE_P1363);
  EXPECT_FALSE(verifier_result.ok()) << verifier_result.status();
}

static util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> GetVerifier(
    const rapidjson::Value& test_group,
    subtle::EcdsaSignatureEncoding encoding) {
  SubtleUtilBoringSSL::EcKey key;
  key.pub_x = WycheproofUtil::GetInteger(test_group["key"]["wx"]);
  key.pub_y = WycheproofUtil::GetInteger(test_group["key"]["wy"]);
  key.curve = WycheproofUtil::GetEllipticCurveType(test_group["key"]["curve"]);
  HashType md = WycheproofUtil::GetHashType(test_group["sha"]);
  auto result = EcdsaVerifyBoringSsl::New(key, md, encoding);
  if (!result.ok()) {
    std::cout << "Failed: " << result.status() << "\n";
  }
  return result;
}

// Tests signature verification using the test vectors in the specified file.
// allow_skipping determines whether it is OK to skip a test because
// a verfier cannot be constructed. This option can be used for
// if a file contains test vectors that are not necessarily supported
// by tink.
bool TestSignatures(const std::string& filename, bool allow_skipping,
                    subtle::EcdsaSignatureEncoding encoding) {
  std::unique_ptr<rapidjson::Document> root =
      WycheproofUtil::ReadTestVectors(filename);
  std::cout << (*root)["algorithm"].GetString();
  std::cout << "generator version " << (*root)["generatorVersion"].GetString();
  std::cout << "expected version 0.2.5";
  int passed_tests = 0;
  int failed_tests = 0;
  for (const rapidjson::Value& test_group : (*root)["testGroups"].GetArray()) {
    auto verifier_result = GetVerifier(test_group, encoding);
    if (!verifier_result.ok()) {
      std::string curve = test_group["key"]["curve"].GetString();
      if (allow_skipping) {
        std::cout << "Could not construct verifier for curve " << curve
                  << verifier_result.status();
      } else {
        ADD_FAILURE() << "Could not construct verifier for curve " << curve
                      << verifier_result.status();
        failed_tests += test_group["tests"].GetArray().Size();
      }
      continue;
    }
    auto verifier = std::move(verifier_result.value());
    for (const rapidjson::Value& test : test_group["tests"].GetArray()) {
      std::string expected = test["result"].GetString();
      std::string msg = WycheproofUtil::GetBytes(test["msg"]);
      std::string sig = WycheproofUtil::GetBytes(test["sig"]);
      std::string id =
          absl::StrCat(test["tcId"].GetInt(), " ", test["comment"].GetString());
      auto status = verifier->Verify(sig, msg);
      if (expected == "valid") {
        if (status.ok()) {
          ++passed_tests;
        } else {
          ++failed_tests;
          ADD_FAILURE() << "Valid signature not verified:" << id
              << " status:" << status;
        }
      } else if (expected == "invalid") {
        if (!status.ok()) {
          ++passed_tests;
        } else {
          ++failed_tests;
          ADD_FAILURE() << "Invalid signature verified:" << id;
        }
      } else if (expected == "acceptable") {
        // The validity of the signature is undefined. Hence the test passes
        // but we log the result since we might still want to know if the
        // library is strict or forgiving.
        ++passed_tests;
        std::cout << "Acceptable signature:" << id << ":" << status;
      } else {
        ++failed_tests;
        ADD_FAILURE() << "Invalid field result:" << expected;
      }
    }
  }
  int num_tests = (*root)["numberOfTests"].GetInt();
  std::cout << "total number of tests: " << num_tests;
  std::cout << "number of tests passed:" << passed_tests;
  std::cout << "number of tests failed:" << failed_tests;
  return failed_tests == 0;
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP256) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp256r1_sha256_test.json", false,
                             subtle::EcdsaSignatureEncoding::DER));
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP384) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp384r1_sha512_test.json", false,
                             subtle::EcdsaSignatureEncoding::DER));
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP521) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp521r1_sha512_test.json", false,
                             subtle::EcdsaSignatureEncoding::DER));
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofWithIeeeP1363Encoding) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_webcrypto_test.json", true,
                             subtle::EcdsaSignatureEncoding::IEEE_P1363));
}

// FIPS-only mode test
TEST_F(EcdsaVerifyBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  auto ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256).value();
  EXPECT_THAT(EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256,
                                        EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));

  ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P384).value();
  EXPECT_THAT(EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256,
                                        EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));

  ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P521).value();
  EXPECT_THAT(EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256,
                                        EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
