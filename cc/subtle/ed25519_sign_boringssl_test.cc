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

#include "tink/subtle/ed25519_sign_boringssl.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/ec_util.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/ed25519_verify_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

constexpr int kEd25519SignatureLenInBytes = 64;

class Ed25519SignBoringSslTest : public ::testing::Test {};

struct Ed25519KeyPair {
  std::string public_key;
  util::SecretData private_key;
};

util::StatusOr<Ed25519KeyPair> NewKeyPair() {
  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key =
      internal::NewEd25519Key();
  if (!key.ok()) {
    return key.status();
  }

  return {{(*key)->public_key, util::SecretDataFromStringView(absl::StrCat(
                                   (*key)->private_key, (*key)->public_key))}};
}

TEST_F(Ed25519SignBoringSslTest, testBasicSign) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  // Generate a new key pair.
  util::StatusOr<Ed25519KeyPair> key = NewKeyPair();
  ASSERT_THAT(key.status(), IsOk());

  // Create a new signer.
  auto signer_result = Ed25519SignBoringSsl::New(key->private_key);
  ASSERT_TRUE(signer_result.ok()) << signer_result.status();
  auto signer = std::move(signer_result.value());

  // Create a new verifier.
  auto verifier_result = Ed25519VerifyBoringSsl::New(key->public_key);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.value());

  // Sign a message.
  std::string message = "some data to be signed";
  std::string signature = signer->Sign(message).value();
  EXPECT_NE(signature, message);
  EXPECT_EQ(signature.size(), kEd25519SignatureLenInBytes);
  auto status = verifier->Verify(signature, message);
  EXPECT_TRUE(status.ok()) << status;

  status = verifier->Verify("some bad signature", message);
  EXPECT_FALSE(status.ok());

  status = verifier->Verify(signature, "some bad message");
  EXPECT_FALSE(status.ok());

  // Loop 100 times, sign a random message twice using the signer and verify
  // that the signatures are the same.
  for (size_t i = 0; i < 100; i++) {
    message = subtle::Random::GetRandomBytes(i);
    std::string signature1 = signer->Sign(message).value();
    std::string signature2 = signer->Sign(message).value();
    EXPECT_EQ(signature1, signature2);
    // Verify that the signatures are valid.
    status = verifier->Verify(signature1, message);
    EXPECT_TRUE(status.ok()) << status;
  }
}

TEST_F(Ed25519SignBoringSslTest, testInvalidPrivateKeys) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  for (int keysize = 0; keysize < 128; keysize++) {
    // Ed25519SignBoringSsl::New expects a private key: private part || public
    // part.
    if (keysize ==
        internal::Ed25519KeyPrivKeySize() + internal::Ed25519KeyPubKeySize()) {
      // Valid key size.
      continue;
    }
    util::SecretData key(keysize, 'x');
    EXPECT_FALSE(Ed25519SignBoringSsl::New(key).ok());
  }
}

TEST_F(Ed25519SignBoringSslTest, testMessageEmptyVersusNullStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  // Generate a new key pair.
  util::StatusOr<Ed25519KeyPair> key = NewKeyPair();
  ASSERT_THAT(key.status(), IsOk());

  // Create a new signer.
  auto signer_result = Ed25519SignBoringSsl::New(key->private_key);
  ASSERT_TRUE(signer_result.ok()) << signer_result.status();
  auto signer = std::move(signer_result.value());

  // Create a new verifier.
  auto verifier_result = Ed25519VerifyBoringSsl::New(key->public_key);
  ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
  auto verifier = std::move(verifier_result.value());

  // Message is a null string_view.
  const absl::string_view empty_message;
  auto signature = signer->Sign(empty_message).value();
  EXPECT_NE(signature, empty_message);
  EXPECT_EQ(signature.size(), kEd25519SignatureLenInBytes);
  auto status = verifier->Verify(signature, empty_message);
  EXPECT_TRUE(status.ok()) << status;

  // Message is an empty string.
  const std::string message = "";
  signature = signer->Sign(message).value();
  EXPECT_EQ(signature.size(), kEd25519SignatureLenInBytes);
  EXPECT_NE(signature, message);
  status = verifier->Verify(signature, message);
  EXPECT_TRUE(status.ok()) << status;

  // Message is a default constructed string_view.
  signature = signer->Sign(absl::string_view()).value();
  EXPECT_EQ(signature.size(), kEd25519SignatureLenInBytes);
  status = verifier->Verify(signature, absl::string_view());
  EXPECT_TRUE(status.ok()) << status;
}

struct TestVector {
  std::string public_key;
  std::string private_key;
  std::string expected_signature;
  std::string message;
};

TEST_F(Ed25519SignBoringSslTest, testWithTestVectors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  // These test vectors are taken from:
  // https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02#section-6.
  TestVector ed25519_vectors[] = {
      {
          /*TEST 1*/
          /*public_key= */ absl::HexStringToBytes(
              "d75a980182b10ab7d54bfed3c964073a"
              "0ee172f3daa62325af021a68f707511a"),
          /*private_key=*/
          absl::HexStringToBytes("9d61b19deffd5a60ba844af492ec2cc4"
                                 "4449c5697b326919703bac031cae7f60"),
          /*signature = */
          absl::HexStringToBytes("e5564300c360ac729086e2cc806e828a"
                                 "84877f1eb8e5d974d873e06522490155"
                                 "5fb8821590a33bacc61e39701cf9b46b"
                                 "d25bf5f0595bbe24655141438e7a100b"),
          /*message = */ "",
      },
      {
          /*TEST 2*/
          /*public_key= */ absl::HexStringToBytes(
              "3d4017c3e843895a92b70aa74d1b7ebc"
              "9c982ccf2ec4968cc0cd55f12af4660c"),
          /*private_key=*/
          absl::HexStringToBytes("4ccd089b28ff96da9db6c346ec114e0f"
                                 "5b8a319f35aba624da8cf6ed4fb8a6fb"),
          /*signature = */
          absl::HexStringToBytes("92a009a9f0d4cab8720e820b5f642540"
                                 "a2b27b5416503f8fb3762223ebdb69da"
                                 "085ac1e43e15996e458f3613d0f11d8c"
                                 "387b2eaeb4302aeeb00d291612bb0c00"),
          /*message = */ "\x72",
      },
      {
          /*TEST 3*/
          /*public_key= */ absl::HexStringToBytes(
              "fc51cd8e6218a1a38da47ed00230f058"
              "0816ed13ba3303ac5deb911548908025"),
          /*private_key=*/
          absl::HexStringToBytes("c5aa8df43f9f837bedb7442f31dcb7b1"
                                 "66d38535076f094b85ce3a2e0b4458f7"),
          /*signature = */
          absl::HexStringToBytes("6291d657deec24024827e69c3abe01a3"
                                 "0ce548a284743a445e3680d7db5ac3ac"
                                 "18ff9b538d16f290ae67f760984dc659"
                                 "4a7c15e9716ed28dc027beceea1ec40a"),
          /*message = */ "\xaf\x82",
      },
      {
          /*TEST 1024*/
          /*public_key= */ absl::HexStringToBytes(
              "278117fc144c72340f67d0f2316e8386"
              "ceffbf2b2428c9c51fef7c597f1d426e"),
          /*private_key=*/
          absl::HexStringToBytes("f5e5767cf153319517630f226876b86c"
                                 "8160cc583bc013744c6bf255f5cc0ee5"),
          /*signature = */
          absl::HexStringToBytes("0aab4c900501b3e24d7cdf4663326a3a"
                                 "87df5e4843b2cbdb67cbf6e460fec350"
                                 "aa5371b1508f9f4528ecea23c436d94b"
                                 "5e8fcd4f681e30a6ac00a9704a188a03"),
          /*message = */
          absl::HexStringToBytes("08b8b2b733424243760fe426a4b54908"
                                 "632110a66c2f6591eabd3345e3e4eb98"
                                 "fa6e264bf09efe12ee50f8f54e9f77b1"
                                 "e355f6c50544e23fb1433ddf73be84d8"
                                 "79de7c0046dc4996d9e773f4bc9efe57"
                                 "38829adb26c81b37c93a1b270b20329d"
                                 "658675fc6ea534e0810a4432826bf58c"
                                 "941efb65d57a338bbd2e26640f89ffbc"
                                 "1a858efcb8550ee3a5e1998bd177e93a"
                                 "7363c344fe6b199ee5d02e82d522c4fe"
                                 "ba15452f80288a821a579116ec6dad2b"
                                 "3b310da903401aa62100ab5d1a36553e"
                                 "06203b33890cc9b832f79ef80560ccb9"
                                 "a39ce767967ed628c6ad573cb116dbef"
                                 "efd75499da96bd68a8a97b928a8bbc10"
                                 "3b6621fcde2beca1231d206be6cd9ec7"
                                 "aff6f6c94fcd7204ed3455c68c83f4a4"
                                 "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
                                 "85ce81bd84359d44254d95629e9855a9"
                                 "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
                                 "d17ba70eb6248e594e1a2297acbbb39d"
                                 "502f1a8c6eb6f1ce22b3de1a1f40cc24"
                                 "554119a831a9aad6079cad88425de6bd"
                                 "e1a9187ebb6092cf67bf2b13fd65f270"
                                 "88d78b7e883c8759d2c4f5c65adb7553"
                                 "878ad575f9fad878e80a0c9ba63bcbcc"
                                 "2732e69485bbc9c90bfbd62481d9089b"
                                 "eccf80cfe2df16a2cf65bd92dd597b07"
                                 "07e0917af48bbb75fed413d238f5555a"
                                 "7a569d80c3414a8d0859dc65a46128ba"
                                 "b27af87a71314f318c782b23ebfe808b"
                                 "82b0ce26401d2e22f04d83d1255dc51a"
                                 "ddd3b75a2b1ae0784504df543af8969b"
                                 "e3ea7082ff7fc9888c144da2af58429e"
                                 "c96031dbcad3dad9af0dcbaaaf268cb8"
                                 "fcffead94f3c7ca495e056a9b47acdb7"
                                 "51fb73e666c6c655ade8297297d07ad1"
                                 "ba5e43f1bca32301651339e22904cc8c"
                                 "42f58c30c04aafdb038dda0847dd988d"
                                 "cda6f3bfd15c4b4c4525004aa06eeff8"
                                 "ca61783aacec57fb3d1f92b0fe2fd1a8"
                                 "5f6724517b65e614ad6808d6f6ee34df"
                                 "f7310fdc82aebfd904b01e1dc54b2927"
                                 "094b2db68d6f903b68401adebf5a7e08"
                                 "d78ff4ef5d63653a65040cf9bfd4aca7"
                                 "984a74d37145986780fc0b16ac451649"
                                 "de6188a7dbdf191f64b5fc5e2ab47b57"
                                 "f7f7276cd419c17a3ca8e1b939ae49e4"
                                 "88acba6b965610b5480109c8b17b80e1"
                                 "b7b750dfc7598d5d5011fd2dcc5600a3"
                                 "2ef5b52a1ecc820e308aa342721aac09"
                                 "43bf6686b64b2579376504ccc493d97e"
                                 "6aed3fb0f9cd71a43dd497f01f17c0e2"
                                 "cb3797aa2a2f256656168e6c496afc5f"
                                 "b93246f6b1116398a346f1a641f3b041"
                                 "e989f7914f90cc2c7fff357876e506b5"
                                 "0d334ba77c225bc307ba537152f3f161"
                                 "0e4eafe595f6d9d90d11faa933a15ef1"
                                 "369546868a7f3a45a96768d40fd9d034"
                                 "12c091c6315cf4fde7cb68606937380d"
                                 "b2eaaa707b4c4185c32eddcdd306705e"
                                 "4dc1ffc872eeee475a64dfac86aba41c"
                                 "0618983f8741c5ef68d3a101e8a3b8ca"
                                 "c60c905c15fc910840b94c00a0b9d0"),
      },
  };

  for (const TestVector &v : ed25519_vectors) {
    // Add the public as a suffix to the private key. This is needed by the
    // boringssl API.
    util::SecretData private_key = util::SecretDataFromStringView(
        absl::StrCat(v.private_key, v.public_key));

    // Create a new signer.
    auto signer_result = Ed25519SignBoringSsl::New(private_key);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.value());

    // Create a new verifier.
    auto verifier_result = Ed25519VerifyBoringSsl::New(v.public_key);
    ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
    auto verifier = std::move(verifier_result.value());

    std::string signature = signer->Sign(v.message).value();
    EXPECT_TRUE(signature == v.expected_signature);

    auto status = verifier->Verify(signature, v.message);
    EXPECT_TRUE(status.ok()) << status;
  }
}

TEST_F(Ed25519SignBoringSslTest, testFipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  // Generate a new key pair.
  util::StatusOr<Ed25519KeyPair> key = NewKeyPair();
  ASSERT_THAT(key.status(), IsOk());

  // Create a new signer.
  EXPECT_THAT(Ed25519SignBoringSsl::New(key->private_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
