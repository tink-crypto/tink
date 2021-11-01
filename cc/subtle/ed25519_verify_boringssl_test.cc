// Copyright 2019 Google Inc.
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

#include "tink/subtle/ed25519_verify_boringssl.h"

#include <string>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/curve25519.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/config/tink_fips.h"
#include "tink/subtle/ed25519_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::StatusIs;

class Ed25519VerifyBoringSslTest : public ::testing::Test {};

TEST_F(Ed25519VerifyBoringSslTest, testBasicSign) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips is false.";
  }

  // Generate a new key pair.
  uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t out_private_key[ED25519_PRIVATE_KEY_LEN];

  ED25519_keypair(out_public_key, out_private_key);

  std::string public_key(reinterpret_cast<const char*>(out_public_key),
                         ED25519_PUBLIC_KEY_LEN);
  util::SecretData private_key(out_private_key,
                               out_private_key + ED25519_PRIVATE_KEY_LEN);

  // Create a new signer.
  auto signer_result = Ed25519SignBoringSsl::New(private_key);
  ASSERT_TRUE(signer_result.ok()) << signer_result.status();
  auto signer = std::move(signer_result.ValueOrDie());

  // Create a new verifier.
  auto verifier_result = Ed25519VerifyBoringSsl::New(public_key);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.ValueOrDie());

  // Sign a message.
  std::string message = "some data to be signed";
  std::string signature = signer->Sign(message).ValueOrDie();
  EXPECT_NE(signature, message);
  EXPECT_EQ(signature.size(), ED25519_SIGNATURE_LEN);
  auto status = verifier->Verify(signature, message);
  EXPECT_TRUE(status.ok()) << status;

  status = verifier->Verify("some bad signature", message);
  EXPECT_FALSE(status.ok());

  status = verifier->Verify(signature, "some bad message");
  EXPECT_FALSE(status.ok());
}

TEST_F(Ed25519VerifyBoringSslTest, testInvalidPublicKeys) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips is false.";
  }

  // Null public key.
  const absl::string_view null_public_key;
  EXPECT_FALSE(Ed25519VerifyBoringSsl::New(null_public_key).ok());

  for (int keysize = 0; keysize < 128; keysize++) {
    if (keysize == ED25519_PUBLIC_KEY_LEN) {
      // Valid key size.
      continue;
    }
    std::string key(keysize, 'x');
    EXPECT_FALSE(Ed25519VerifyBoringSsl::New(key).ok());
  }
}

TEST_F(Ed25519VerifyBoringSslTest, testMessageEmptyVersusNullStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips is false.";
  }

  // Generate a new key pair.
  uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t out_private_key[ED25519_PRIVATE_KEY_LEN];

  ED25519_keypair(out_public_key, out_private_key);

  std::string public_key(reinterpret_cast<const char*>(out_public_key),
                         ED25519_PUBLIC_KEY_LEN);
  util::SecretData private_key(out_private_key,
                               out_private_key + ED25519_PRIVATE_KEY_LEN);

  // Create a new signer.
  auto signer_result = Ed25519SignBoringSsl::New(private_key);
  ASSERT_TRUE(signer_result.ok()) << signer_result.status();
  auto signer = std::move(signer_result.ValueOrDie());

  // Create a new verifier.
  auto verifier_result = Ed25519VerifyBoringSsl::New(public_key);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.ValueOrDie());

  // Message is a null string_view.
  const absl::string_view empty_message;
  auto signature = signer->Sign(empty_message).ValueOrDie();
  EXPECT_NE(signature, empty_message);
  EXPECT_EQ(signature.size(), ED25519_SIGNATURE_LEN);
  auto status = verifier->Verify(signature, empty_message);
  EXPECT_TRUE(status.ok()) << status;

  // Message is an empty string.
  const std::string message = "";
  signature = signer->Sign(message).ValueOrDie();
  EXPECT_EQ(signature.size(), ED25519_SIGNATURE_LEN);
  EXPECT_NE(signature, message);
  status = verifier->Verify(signature, message);
  EXPECT_TRUE(status.ok()) << status;

  // Message is a default constructed string_view.
  signature = signer->Sign(absl::string_view()).ValueOrDie();
  EXPECT_EQ(signature.size(), ED25519_SIGNATURE_LEN);
  status = verifier->Verify(signature, absl::string_view());
  EXPECT_TRUE(status.ok()) << status;
}

static util::StatusOr<std::unique_ptr<PublicKeyVerify>> GetVerifier(
    const rapidjson::Value& test_group) {
  std::string public_key = WycheproofUtil::GetBytes(test_group["key"]["pk"]);
  auto result = Ed25519VerifyBoringSsl::New(public_key);
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
  int passed_tests = 0;
  int failed_tests = 0;
  for (const rapidjson::Value& test_group : (*root)["testGroups"].GetArray()) {
    auto verifier_result = GetVerifier(test_group);
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

    auto verifier = std::move(verifier_result.ValueOrDie());
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

TEST_F(Ed25519VerifyBoringSslTest, WycheproofCurve25519) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips is false.";
  }

  ASSERT_TRUE(TestSignatures("eddsa_test.json", false));
}

TEST_F(Ed25519VerifyBoringSslTest, testFipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips.";
  }

  // Generate a new key pair.
  uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN];
  util::SecretData private_key(ED25519_PRIVATE_KEY_LEN);
  ED25519_keypair(out_public_key, private_key.data());

  std::string public_key(reinterpret_cast<const char *>(out_public_key),
                         ED25519_PUBLIC_KEY_LEN);

  // Create a new signer.
  EXPECT_THAT(Ed25519VerifyBoringSsl::New(public_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
