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

#include <string>

#include "absl/strings/str_cat.h"
#include "include/rapidjson/document.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class EcdsaVerifyBoringSslTest : public ::testing::Test {};

TEST_F(EcdsaVerifyBoringSslTest, testBasicSigning) {
  auto ec_key_result = SubtleUtilBoringSSL::GetNewEcKey(
      EllipticCurveType::NIST_P256);
  ASSERT_TRUE(ec_key_result.ok()) << ec_key_result.status();
  auto ec_key = std::move(ec_key_result.ValueOrDie());

  auto signer_result = EcdsaSignBoringSsl::New(ec_key, HashType::SHA256);
  ASSERT_TRUE(signer_result.ok()) << signer_result.status();
  auto signer = std::move(signer_result.ValueOrDie());

  auto verifier_result = EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.ValueOrDie());

  std::string message = "some data to be signed";
  auto sign_result = signer->Sign(message);
  ASSERT_TRUE(sign_result.ok()) << sign_result.status();
  std::string signature = sign_result.ValueOrDie();
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

TEST_F(EcdsaVerifyBoringSslTest, testNewErrors) {
  auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256)
                    .ValueOrDie();
  auto verifier_result = EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA1);
  EXPECT_FALSE(verifier_result.ok()) << verifier_result.status();
}

// Integers in Wycheproof are represented as signed bigendian hexadecimal
// strings in twos complement representation.
// Integers in EcKey are unsigned and are represented as an array of bytes
// using bigendian order.
// GetInteger can assume that val is always 0 or a positive integer, since
// they are values from the key: a convention in Wycheproof is that parameters
// in the test group are valid, only values in the test vector itself may
// be invalid.
static std::string GetInteger(const rapidjson::Value &val) {
  std::string hex(val.GetString());
  // Since val is a hexadecimal integer it can have an odd length.
  if (hex.size() % 2 == 1) {
    // Avoid a leading 0 byte.
    if (hex[0] == '0') {
      hex = std::string(hex, 1, hex.size()-1);
    } else {
      hex = "0" + hex;
    }
  }
  return test::HexDecodeOrDie(hex);
}

static util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>>
GetVerifier(const rapidjson::Value &test_group) {
  SubtleUtilBoringSSL::EcKey key;
  key.pub_x = GetInteger(test_group["key"]["wx"]);
  key.pub_y = GetInteger(test_group["key"]["wy"]);
  key.curve = WycheproofUtil::GetEllipticCurveType(test_group["key"]["curve"]);
  HashType md = WycheproofUtil::GetHashType(test_group["sha"]);
  auto result = EcdsaVerifyBoringSsl::New(key, md);
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
bool TestSignatures(const std::string& filename, bool allow_skipping) {
  std::unique_ptr<rapidjson::Document> root =
      WycheproofUtil::ReadTestVectors(filename);
  std::cout << (*root)["algorithm"].GetString();
  std::cout << "generator version " << (*root)["generatorVersion"].GetString();
  std::cout << "expected version 0.2.5";
  int passed_tests = 0;
  int failed_tests = 0;
    std::cout << "here0\n";
  for (const rapidjson::Value& test_group : (*root)["testGroups"].GetArray()) {
    std::cout << "here1\n";
    auto verifier_result = GetVerifier(test_group);
    std::cout << "here2\n";
    if (!verifier_result.ok()) {
      std::string curve = test_group["key"]["curve"].GetString();
      if (allow_skipping) {
        std::cout << "Could not construct verifier for curve " << curve;
      } else {
        ADD_FAILURE() << "Could not construct verifier for curve " << curve;
        failed_tests += test_group["tests"].GetArray().Size();
      }
      continue;
    }
    std::cout << "here3\n";
    auto verifier = std::move(verifier_result.ValueOrDie());
    std::cout << "here4\n";
    for (const rapidjson::Value& test : test_group["tests"].GetArray()) {
      std::string expected = test["result"].GetString();
      std::string msg = WycheproofUtil::GetBytes(test["msg"]);
      std::string sig = WycheproofUtil::GetBytes(test["sig"]);
      std::string id = absl::StrCat(test["tcId"].GetInt(), " ",
                               test["comment"].GetString());
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

TEST_F(EcdsaVerifyBoringSslTest, testVectorsNistP256) {
  ASSERT_TRUE(TestSignatures("ecdsa_secp256r1_sha256_test.json", false));
}

TEST_F(EcdsaVerifyBoringSslTest, testVectorsNistP384) {
  ASSERT_TRUE(TestSignatures("ecdsa_secp384r1_sha512_test.json", false));
}

TEST_F(EcdsaVerifyBoringSslTest, testVectorsNistP521) {
  ASSERT_TRUE(TestSignatures("ecdsa_secp521r1_sha512_test.json", false));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

int main(int ac, char *av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
