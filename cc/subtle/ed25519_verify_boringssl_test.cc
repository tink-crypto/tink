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

#include <memory>
#include <string>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/ec_util.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/wycheproof_util.h"
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
using ::testing::Not;
using ::testing::Test;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

// Non-FIPS tests.
class Ed25519VerifyBoringSslTest : public Test {
 private:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
    }
  }
};

// Test vector taken from
// https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02#section-6.
struct TestVector {
  int id;
  std::string public_key;
  std::string private_key;
  std::string signature;
  std::string message;
};

std::vector<TestVector> GetTestVectors() {
  return {
      {
          /*id=*/1,
          /*public_key=*/
          absl::HexStringToBytes(
              "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511"
              "a"),
          /*private_key=*/
          absl::HexStringToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326"
                                 "919703bac031cae7f60"),
          /*signature=*/
          absl::HexStringToBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d"
                                 "974d873e065224901555fb8821590a33bacc61e39701c"
                                 "f9b46bd25bf5f0595bbe24655141438e7a100b"),
          /*message=*/"",
      },
      {
          /*id=*/2,
          /*public_key=*/
          absl::HexStringToBytes(
              "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660"
              "c"),
          /*private_key=*/
          absl::HexStringToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba"
                                 "624da8cf6ed4fb8a6fb"),
          /*signature=*/
          absl::HexStringToBytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503"
                                 "f8fb3762223ebdb69da085ac1e43e15996e458f3613d0"
                                 "f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
          /*message=*/"\x72",
      },
      {
          /*id=*/3,
          /*public_key=*/
          absl::HexStringToBytes(
              "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb91154890802"
              "5"),
          /*private_key=*/
          absl::HexStringToBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f0"
                                 "94b85ce3a2e0b4458f7"),
          /*signature=*/
          absl::HexStringToBytes("6291d657deec24024827e69c3abe01a30ce548a284743"
                                 "a445e3680d7db5ac3ac18ff9b538d16f290ae67f76098"
                                 "4dc6594a7c15e9716ed28dc027beceea1ec40a"),
          /*message=*/"\xaf\x82",
      },
      {
          /*id=*/1024,
          /*public_key=*/
          absl::HexStringToBytes(
              "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426"
              "e"),
          /*private_key=*/
          absl::HexStringToBytes("f5e5767cf153319517630f226876b86c8160cc583bc01"
                                 "3744c6bf255f5cc0ee5"),
          /*signature=*/
          absl::HexStringToBytes("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2c"
                                 "bdb67cbf6e460fec350aa5371b1508f9f4528ecea23c4"
                                 "36d94b5e8fcd4f681e30a6ac00a9704a188a03"),
          /*message=*/
          absl::HexStringToBytes(
              "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
              "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
              "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
              "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
              "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
              "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
              "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
              "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
              "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
              "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
              "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
              "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
              "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
              "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
              "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
              "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
              "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
              "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
              "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
              "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
              "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
              "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
              "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
              "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
              "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
              "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
              "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
              "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
              "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
              "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
              "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
              "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"),
      },
  };
}

TEST_F(Ed25519VerifyBoringSslTest, InvalidPublicKey) {
  // Null public key.
  const absl::string_view null_public_key;
  EXPECT_THAT(Ed25519VerifyBoringSsl::New(null_public_key).status(),
              Not(IsOk()));

  for (int keysize = 0; keysize < 128; keysize++) {
    if (keysize == internal::Ed25519KeyPubKeySize()) {
      // Valid key size.
      continue;
    }
    std::string key(keysize, 'x');
    EXPECT_THAT(Ed25519VerifyBoringSsl::New(key).status(), Not(IsOk()));
  }
}

// Using the test vector with id=1, this makes sure verification succeeds
// passing an empty string_view, an empty string and a default-constructed
// string_view.
TEST_F(Ed25519VerifyBoringSslTest, MessageEmptyVersusNullStringView) {
  TestVector empty_message_test_vector = GetTestVectors()[0];
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      Ed25519VerifyBoringSsl::New(empty_message_test_vector.public_key);
  ASSERT_THAT(verifier.status(), IsOk());

  // Message is a null string_view.
  const absl::string_view kEmptyStringView;
  EXPECT_THAT((*verifier)->Verify(empty_message_test_vector.signature,
                                  kEmptyStringView),
              IsOk());

  // Message is an empty string.
  const std::string kEmptyStr = "";
  EXPECT_THAT(
      (*verifier)->Verify(empty_message_test_vector.signature, kEmptyStr),
      IsOk());

  // Message is a default constructed string_view.
  EXPECT_THAT((*verifier)->Verify(empty_message_test_vector.signature,
                                  absl::string_view()),
              IsOk());
}

using Ed25519VerifyBoringSslParamsTest = TestWithParam<TestVector>;

TEST_P(Ed25519VerifyBoringSslParamsTest, VerifiesCorrectly) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }
  TestVector test_vector = GetParam();

  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      Ed25519VerifyBoringSsl::New(test_vector.public_key);
  ASSERT_THAT(verifier.status(), IsOk());
  EXPECT_THAT((*verifier)->Verify(test_vector.signature, test_vector.message),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(Ed25519VerifyBoringSslParamsTests,
                         Ed25519VerifyBoringSslParamsTest,
                         ValuesIn(GetTestVectors()));

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
  ASSERT_TRUE(TestSignatures("eddsa_test.json", false));
}

TEST(Ed25519VerifyBoringSslFipsTest, testFipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  constexpr absl::string_view kPublicKey =
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
  // Create a new signer.
  EXPECT_THAT(
      Ed25519VerifyBoringSsl::New(absl::HexStringToBytes(kPublicKey)).status(),
      StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
