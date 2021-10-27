// Copyright 2018 Google Inc.
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

#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"

#include <string>

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "include/rapidjson/document.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

// TODO(quannguyen):
//  + Add tests for parameters validation.
namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class RsaSsaPssVerifyBoringSslTest : public ::testing::Test {};

// Test vector from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
struct NistTestVector {
  std::string n;
  std::string e;
  std::string message;
  std::string signature;
  HashType sig_hash;
  HashType mgf1_hash;
  int salt_length;
};

static const NistTestVector nist_test_vector{
    absl::HexStringToBytes(
        "a47d04e7cacdba4ea26eca8a4c6e14563c2ce03b623b768c0d49868a57121301dbf783"
        "d82f4c055e73960e70550187d0af62ac3496f0a3d9103c2eb7919a72752fa7ce8c688d"
        "81e3aee99468887a15288afbb7acb845b7c522b5c64e678fcd3d22feb84b44272700be"
        "527d2b2025a3f83c2383bf6a39cf5b4e48b3cf2f56eef0dfff18555e31037b91524869"
        "4876f3047814415164f2c660881e694b58c28038a032ad25634aad7b39171dee368e3d"
        "59bfb7299e4601d4587e68caaf8db457b75af42fc0cf1ae7caced286d77fac6cedb03a"
        "d94f1433d2c94d08e60bc1fdef0543cd2951e765b38230fdd18de5d2ca627ddc032fe0"
        "5bbd2ff21e2db1c2f94d8b"),
    absl::HexStringToBytes("10e43f"),
    absl::HexStringToBytes(
        "e002377affb04f0fe4598de9d92d31d6c786040d5776976556a2cfc55e54a1dcb3cb1b"
        "126bd6a4bed2a184990ccea773fcc79d246553e6c64f686d21ad4152673cafec22aeb4"
        "0f6a084e8a5b4991f4c64cf8a927effd0fd775e71e8329e41fdd4457b3911173187b4f"
        "09a817d79ea2397fc12dfe3d9c9a0290c8ead31b6690a6"),
    absl::HexStringToBytes(
        "4f9b425c2058460e4ab2f5c96384da2327fd29150f01955a76b4efe956af06dc08779a"
        "374ee4607eab61a93adc5608f4ec36e47f2a0f754e8ff839a8a19b1db1e884ea4cf348"
        "cd455069eb87afd53645b44e28a0a56808f5031da5ba9112768dfbfca44ebe63a0c057"
        "2b731d66122fb71609be1480faa4e4f75e43955159d70f081e2a32fbb19a48b9f162cf"
        "6b2fb445d2d6994bc58910a26b5943477803cdaaa1bd74b0da0a5d053d8b1dc593091d"
        "b5388383c26079f344e2aea600d0e324164b450f7b9b465111b7265f3b1b063089ae7e"
        "2623fc0fda8052cf4bf3379102fbf71d7c98e8258664ceed637d20f95ff0111881e650"
        "ce61f251d9c3a629ef222d"),
    HashType::SHA256,
    HashType::SHA256,
    32};

TEST_F(RsaSsaPssVerifyBoringSslTest, BasicVerify) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  SubtleUtilBoringSSL::RsaPublicKey pub_key{nist_test_vector.n,
                                            nist_test_vector.e};
  SubtleUtilBoringSSL::RsaSsaPssParams params{nist_test_vector.sig_hash,
                                              nist_test_vector.mgf1_hash,
                                              nist_test_vector.salt_length};

  auto verifier_result = RsaSsaPssVerifyBoringSsl::New(pub_key, params);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.ValueOrDie());
  auto status =
      verifier->Verify(nist_test_vector.signature, nist_test_vector.message);
  EXPECT_TRUE(status.ok()) << status << internal::GetSslErrors();
}

TEST_F(RsaSsaPssVerifyBoringSslTest, NewErrors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  SubtleUtilBoringSSL::RsaPublicKey nist_pub_key{nist_test_vector.n,
                                                 nist_test_vector.e};
  SubtleUtilBoringSSL::RsaSsaPssParams nist_params{
      nist_test_vector.sig_hash, nist_test_vector.mgf1_hash,
      nist_test_vector.salt_length};
  SubtleUtilBoringSSL::RsaPublicKey small_pub_key{std::string("\x23"),
                                                  std::string("\x3")};
  SubtleUtilBoringSSL::RsaSsaPssParams sha1_hash_params{
      HashType::SHA1, nist_test_vector.mgf1_hash, nist_test_vector.salt_length};

  {  // Small modulus.
    auto result = RsaSsaPssVerifyBoringSsl::New(small_pub_key, nist_params);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "only modulus size >= 2048-bit is supported",
                        std::string(result.status().message()));
  }

  {  // Use SHA1 for digital signature.
    auto result = RsaSsaPssVerifyBoringSsl::New(nist_pub_key, sha1_hash_params);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "SHA1 is not safe for digital signature",
                        std::string(result.status().message()));
  }
}

TEST_F(RsaSsaPssVerifyBoringSslTest, Modification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  SubtleUtilBoringSSL::RsaPublicKey pub_key{nist_test_vector.n,
                                            nist_test_vector.e};
  SubtleUtilBoringSSL::RsaSsaPssParams params{nist_test_vector.sig_hash,
                                              nist_test_vector.mgf1_hash,
                                              nist_test_vector.salt_length};

  auto verifier_result = RsaSsaPssVerifyBoringSsl::New(pub_key, params);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.ValueOrDie());
  // Modify the message.
  for (std::size_t i = 0; i < nist_test_vector.message.length(); i++) {
    std::string modified_message = nist_test_vector.message;
    modified_message[i / 8] ^= 1 << (i % 8);
    auto status =
        verifier->Verify(nist_test_vector.signature, modified_message);
    EXPECT_FALSE(status.ok()) << status << internal::GetSslErrors();
  }
  // Modify the signature.
  for (std::size_t i = 0; i < nist_test_vector.signature.length(); i++) {
    std::string modified_signature = nist_test_vector.signature;
    modified_signature[i / 8] ^= 1 << (i % 8);
    auto status =
        verifier->Verify(modified_signature, nist_test_vector.message);
    EXPECT_FALSE(status.ok()) << status << internal::GetSslErrors();
  }
  // Truncate the signature.
  for (std::size_t i = 0; i < nist_test_vector.signature.length(); i++) {
    std::string truncated_signature(nist_test_vector.signature, 0, i);
    auto status =
        verifier->Verify(truncated_signature, nist_test_vector.message);
    EXPECT_FALSE(status.ok()) << status << internal::GetSslErrors();
  }
}

static util::StatusOr<std::unique_ptr<RsaSsaPssVerifyBoringSsl>> GetVerifier(
    const rapidjson::Value& test_group) {
  SubtleUtilBoringSSL::RsaPublicKey key;
  key.n = WycheproofUtil::GetInteger(test_group["n"]);
  key.e = WycheproofUtil::GetInteger(test_group["e"]);

  SubtleUtilBoringSSL::RsaSsaPssParams params;
  params.sig_hash = WycheproofUtil::GetHashType(test_group["sha"]);
  params.mgf1_hash = WycheproofUtil::GetHashType(test_group["mgfSha"]);
  params.salt_length = test_group["sLen"].GetInt();

  auto result = RsaSsaPssVerifyBoringSsl::New(key, params);
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
  std::cout << "expected version 0.4.12";
  int passed_tests = 0;
  int failed_tests = 0;
  int group_count = 0;
  for (const rapidjson::Value& test_group : (*root)["testGroups"].GetArray()) {
    group_count++;
    auto verifier_result = GetVerifier(test_group);
    if (!verifier_result.ok()) {
      std::string type = test_group["type"].GetString();
      if (allow_skipping) {
        std::cout << "Could not construct verifier for " << type << " group "
                  << group_count << ": " << verifier_result.status();
      } else {
        ADD_FAILURE() << "Could not construct verifier for " << type
                      << " group " << group_count << ": "
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

TEST_F(RsaSsaPssVerifyBoringSslTest, WycheproofRsaPss2048Sha2560) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  ASSERT_TRUE(TestSignatures("rsa_pss_2048_sha256_mgf1_0_test.json",
                             /*allow_skipping=*/false));
}

TEST_F(RsaSsaPssVerifyBoringSslTest, WycheproofRsaPss2048Sha25632) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  ASSERT_TRUE(TestSignatures("rsa_pss_2048_sha256_mgf1_32_test.json",
                             /*allow_skipping=*/false));
}

TEST_F(RsaSsaPssVerifyBoringSslTest, WycheproofRsaPss3072Sha25632) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("rsa_pss_3072_sha256_mgf1_32_test.json",
                             /*allow_skipping=*/false));
}

TEST_F(RsaSsaPssVerifyBoringSslTest, WycheproofRsaPss4096Sha25632) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  ASSERT_TRUE(TestSignatures("rsa_pss_4096_sha256_mgf1_32_test.json",
                             /*allow_skipping=*/false));
}

TEST_F(RsaSsaPssVerifyBoringSslTest, WycheproofRsaPss4096Sha51232) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  ASSERT_TRUE(TestSignatures("rsa_pss_4096_sha512_mgf1_32_test.json",
                             /*allow_skipping=*/false));
}

// FIPS-only mode test
TEST_F(RsaSsaPssVerifyBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  SubtleUtilBoringSSL::RsaPublicKey pub_key{nist_test_vector.n,
                                            nist_test_vector.e};
  SubtleUtilBoringSSL::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                              /*mgf1_hash=*/HashType::SHA256,
                                              /*salt_length=*/32};
  EXPECT_THAT(RsaSsaPssVerifyBoringSsl::New(pub_key, params).status(),
              StatusIs(util::error::INTERNAL));
}

TEST_F(RsaSsaPssVerifyBoringSslTest, TestAllowedFipsModuli) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  internal::SslUniquePtr<BIGNUM> rsa_f4(BN_new());
  SubtleUtilBoringSSL::RsaPrivateKey private_key;
  SubtleUtilBoringSSL::RsaPublicKey public_key;
  SubtleUtilBoringSSL::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                              /*mgf1_hash=*/HashType::SHA256,
                                              /*salt_length=*/32};
  BN_set_u64(rsa_f4.get(), RSA_F4);

  EXPECT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(3072, rsa_f4.get(),
                                                    &private_key, &public_key),
              IsOk());

  EXPECT_THAT(RsaSsaPssVerifyBoringSsl::New(public_key, params).status(),
              IsOk());
}

TEST_F(RsaSsaPssVerifyBoringSslTest, TestRestrictedFipsModuli) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  internal::SslUniquePtr<BIGNUM> rsa_f4(BN_new());
  SubtleUtilBoringSSL::RsaPrivateKey private_key;
  SubtleUtilBoringSSL::RsaPublicKey public_key;
  SubtleUtilBoringSSL::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                              /*mgf1_hash=*/HashType::SHA256,
                                              /*salt_length=*/32};
  BN_set_u64(rsa_f4.get(), RSA_F4);

  EXPECT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(2048, rsa_f4.get(),
                                                    &private_key, &public_key),
              IsOk());

  EXPECT_THAT(RsaSsaPssVerifyBoringSsl::New(public_key, params).status(),
              StatusIs(util::error::INTERNAL));

  EXPECT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(4096, rsa_f4.get(),
                                                    &private_key, &public_key),
              IsOk());

  EXPECT_THAT(RsaSsaPssVerifyBoringSsl::New(public_key, params).status(),
              StatusIs(util::error::INTERNAL));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
