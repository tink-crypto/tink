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
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"

// TODO(quannguyen):
//  + Add Wycheproof test once it's available.
//  + Add tests for parameters validation.
namespace crypto {
namespace tink {
namespace subtle {
namespace {

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

TEST_F(RsaSsaPssVerifyBoringSslTest, testBasicVerify) {
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
  EXPECT_TRUE(status.ok()) << status << SubtleUtilBoringSSL::GetErrors();
}

TEST_F(RsaSsaPssVerifyBoringSslTest, testNewErrors) {
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
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "only modulus size >= 2048-bit is supported",
                        result.status().error_message());
  }

  {  // Use SHA1 for digital signature.
    auto result = RsaSsaPssVerifyBoringSsl::New(nist_pub_key, sha1_hash_params);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "SHA1 is not safe for digital signature",
                        result.status().error_message());
  }
}

TEST_F(RsaSsaPssVerifyBoringSslTest, testModification) {
  SubtleUtilBoringSSL::RsaPublicKey pub_key{nist_test_vector.n,
                                            nist_test_vector.e};
  SubtleUtilBoringSSL::RsaSsaPssParams params{nist_test_vector.sig_hash,
                                              nist_test_vector.mgf1_hash,
                                              nist_test_vector.salt_length};

  auto verifier_result = RsaSsaPssVerifyBoringSsl::New(pub_key, params);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.ValueOrDie());
  // Modify the message.
  for (int i = 0; i < nist_test_vector.message.length(); i++) {
    std::string modified_message = nist_test_vector.message;
    modified_message[i / 8] ^= 1 << (i % 8);
    auto status =
        verifier->Verify(nist_test_vector.signature, modified_message);
    EXPECT_FALSE(status.ok()) << status << SubtleUtilBoringSSL::GetErrors();
  }
  // Modify the signature.
  for (int i = 0; i < nist_test_vector.signature.length(); i++) {
    std::string modified_signature = nist_test_vector.signature;
    modified_signature[i / 8] ^= 1 << (i % 8);
    auto status =
        verifier->Verify(modified_signature, nist_test_vector.message);
    EXPECT_FALSE(status.ok()) << status << SubtleUtilBoringSSL::GetErrors();
  }
  // Truncate the signature.
  for (int i = 0; i < nist_test_vector.signature.length(); i++) {
    std::string truncated_signature(nist_test_vector.signature, 0, i);
    auto status =
        verifier->Verify(truncated_signature, nist_test_vector.message);
    EXPECT_FALSE(status.ok()) << status << SubtleUtilBoringSSL::GetErrors();
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
