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

#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"

#include <iostream>
#include <string>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "include/rapidjson/document.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/err_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

class RsaSsaPkcs1VerifyBoringSslTest : public ::testing::Test {};

// Test vector from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
struct NistTestVector {
  std::string n;
  std::string e;
  std::string message;
  std::string signature;
  HashType sig_hash;
};

static const NistTestVector nist_test_vector{
    absl::HexStringToBytes(
        "c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026bcb2399"
        "bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae852087d25f1d260cc"
        "74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d11542a705f83ae96d2"
        "a49763d5fbb24398edf3702bc94bc168190166492b8671de874bb9cecb058c6c8344aa"
        "8c93754d6effcd44a41ed7de0a9dcd9144437f212b18881d042d331a4618a9e630ef9b"
        "b66305e4fdf8f0391b3b2313fe549f0189ff968b92f33c266a4bc2cffc897d1937eeb9"
        "e406f5d0eaa7a14782e76af3fce98f54ed237b4a04a4159a5f6250a296a902880204e6"
        "1d891c4da29f2d65f34cbb"),
    absl::HexStringToBytes("49d2a1"),
    absl::HexStringToBytes(
        "95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad756fbd91"
        "8c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632ad30b3dc3ce0b"
        "a97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af590824ca98d74fbca934"
        "d0b6867aa1991f3040b707e806de6e66b5934f05509bea"),
    absl::HexStringToBytes(
        "51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027d39365"
        "de70a31db05e9e10eb6148cb7f6425f0c93c4fb0e2291adbd22c77656afc196858a11e"
        "1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd509e896f63884e9424"
        "f69c1c5397959f1e52a368667a598a1fc90125273d9341295d2f8e1cc4969bf228c860"
        "e07a3546be2eeda1cde48ee94d062801fe666e4a7ae8cb9cd79262c017b081af874ff0"
        "0453ca43e34efdb43fffb0bb42a4e2d32a5e5cc9e8546a221fe930250e5f5333e0efe5"
        "8ffebf19369a3b8ae5a67f6a048bc9ef915bda25160729b508667ada84a0c27e7e26cf"
        "2abca413e5e4693f4a9405"),
    HashType::SHA256};

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, BasicVerify) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaPublicKey pub_key{nist_test_vector.n, nist_test_vector.e};
  internal::RsaSsaPkcs1Params params{nist_test_vector.sig_hash};

  auto verifier_result = RsaSsaPkcs1VerifyBoringSsl::New(pub_key, params);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.ValueOrDie());
  auto status =
      verifier->Verify(nist_test_vector.signature, nist_test_vector.message);
  EXPECT_TRUE(status.ok()) << status << internal::GetSslErrors();
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, NewErrors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaPublicKey nist_pub_key{nist_test_vector.n, nist_test_vector.e};
  internal::RsaSsaPkcs1Params nist_params{nist_test_vector.sig_hash};
  internal::RsaPublicKey small_pub_key{std::string("\x23"), std::string("\x3")};
  internal::RsaSsaPkcs1Params sha1_hash_params{HashType::SHA1};

  {  // Small modulus.
    auto result = RsaSsaPkcs1VerifyBoringSsl::New(small_pub_key, nist_params);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "only modulus size >= 2048-bit is supported",
                        std::string(result.status().message()));
  }

  {  // Use SHA1 for digital signature.
    auto result =
        RsaSsaPkcs1VerifyBoringSsl::New(nist_pub_key, sha1_hash_params);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "SHA1 is not safe for digital signature",
                        std::string(result.status().message()));
  }
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, Modification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaPublicKey pub_key{nist_test_vector.n, nist_test_vector.e};
  internal::RsaSsaPkcs1Params params{nist_test_vector.sig_hash};

  auto verifier_result = RsaSsaPkcs1VerifyBoringSsl::New(pub_key, params);
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

static util::StatusOr<std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl>> GetVerifier(
    const rapidjson::Value& test_group) {
  internal::RsaPublicKey key;
  key.n = WycheproofUtil::GetInteger(test_group["n"]);
  key.e = WycheproofUtil::GetInteger(test_group["e"]);

  HashType md = WycheproofUtil::GetHashType(test_group["sha"]);
  internal::RsaSsaPkcs1Params params;
  params.hash_type = md;

  auto result = RsaSsaPkcs1VerifyBoringSsl::New(key, params);
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

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, WycheproofRsaPkcs12048SHA256) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  ASSERT_TRUE(TestSignatures("rsa_signature_2048_sha256_test.json",
                             /*allow_skipping=*/true));
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, WycheproofRsaPkcs13072SHA256) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("rsa_signature_3072_sha256_test.json",
                             /*allow_skipping=*/true));
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, WycheproofRsaPkcs13072SHA512) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("rsa_signature_3072_sha512_test.json",
                             /*allow_skipping=*/true));
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, WycheproofRsaPkcs14096SHA512) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  ASSERT_TRUE(TestSignatures("rsa_signature_4096_sha512_test.json",
                             /*allow_skipping=*/true));
}

// FIPS-only mode test
TEST_F(RsaSsaPkcs1VerifyBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  internal::RsaPublicKey pub_key{nist_test_vector.n, nist_test_vector.e};
  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  EXPECT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(pub_key, params).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, TestAllowedFipsModuli) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  internal::SslUniquePtr<BIGNUM> rsa_f4(BN_new());
  internal::RsaPrivateKey private_key;
  internal::RsaPublicKey public_key;
  BN_set_u64(rsa_f4.get(), RSA_F4);

  EXPECT_THAT(
      internal::NewRsaKeyPair(3072, rsa_f4.get(), &private_key, &public_key),
      IsOk());

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  EXPECT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(public_key, params).status(),
              IsOk());
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, TestRestrictedFipsModuli) {
  if (!IsFipsModeEnabled() || !FIPS_mode()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  internal::SslUniquePtr<BIGNUM> rsa_f4(BN_new());
  internal::RsaPrivateKey private_key;
  internal::RsaPublicKey public_key;
  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  BN_set_u64(rsa_f4.get(), RSA_F4);

  EXPECT_THAT(
      internal::NewRsaKeyPair(2560, rsa_f4.get(), &private_key, &public_key),
      IsOk());

  EXPECT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(public_key, params).status(),
              StatusIs(absl::StatusCode::kInternal));

  EXPECT_THAT(
      internal::NewRsaKeyPair(4096, rsa_f4.get(), &private_key, &public_key),
      IsOk());

  EXPECT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(public_key, params).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
