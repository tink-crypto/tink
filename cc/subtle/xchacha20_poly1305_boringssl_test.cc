// Copyright 2018 Google Inc.
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

#include "tink/subtle/xchacha20_poly1305_boringssl.h"

#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/ssl_util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

constexpr int kNonceSizeInBytes = 24;
constexpr int kTagSizeInBytes = 16;

constexpr absl::string_view kKey256Hex =
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAssociatedData = "Some data to authenticate.";

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

TEST(XChacha20Poly1305BoringSslTest, EncryptDecrypt) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256Hex));
  if (!internal::IsBoringSsl()) {
    EXPECT_THAT(XChacha20Poly1305BoringSsl::New(key).status(),
                StatusIs(absl::StatusCode::kUnimplemented));
  } else {
    util::StatusOr<std::unique_ptr<Aead>> aead =
        XChacha20Poly1305BoringSsl::New(key);
    ASSERT_THAT(aead.status(), IsOk());

    util::StatusOr<std::string> ciphertext =
        (*aead)->Encrypt(kMessage, kAssociatedData);
    ASSERT_THAT(ciphertext.status(), IsOk());
    EXPECT_THAT(*ciphertext,
                SizeIs(kMessage.size() + kNonceSizeInBytes + kTagSizeInBytes));
    util::StatusOr<std::string> plaintext =
        (*aead)->Decrypt(*ciphertext, kAssociatedData);
    ASSERT_THAT(plaintext.status(), IsOk());
    EXPECT_EQ(*plaintext, kMessage);
  }
}

// Test decryption with a known ciphertext, message, associated_data and key
// tuple to make sure this is using the correct algorithm. The values are taken
// from the test vector tcId 1 of the Wycheproof tests:
// https://github.com/google/wycheproof/blob/master/testvectors/xchacha20_poly1305_test.json#L21
TEST(XChacha20Poly1305BoringSslTest, SimpleDecrypt) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  std::string message = absl::HexStringToBytes(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66"
      "202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e6520"
      "74697020666f7220746865206675747572652c2073756e73637265656e20776f756c6420"
      "62652069742e");
  std::string raw_ciphertext = absl::HexStringToBytes(
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b"
      "0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945"
      "b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f6"
      "15c68b13b52e");
  std::string iv = absl::HexStringToBytes(
      "404142434445464748494a4b4c4d4e4f5051525354555657");
  std::string tag = absl::HexStringToBytes("c0875924c1c7987947deafd8780acf49");
  std::string associated_data =
      absl::HexStringToBytes("50515253c0c1c2c3c4c5c6c7");
  util::SecretData key = util::SecretDataFromStringView(absl::HexStringToBytes(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));

  util::StatusOr<std::unique_ptr<Aead>> aead =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(aead.status(), IsOk());

  util::StatusOr<std::string> plaintext =
      (*aead)->Decrypt(absl::StrCat(iv, raw_ciphertext, tag), associated_data);
  ASSERT_THAT(plaintext.status(), IsOk());
  EXPECT_EQ(*plaintext, message);
}

TEST(XChacha20Poly1305BoringSslTest, DecryptFailsIfCiphertextTooSmall) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256Hex));
  util::StatusOr<std::unique_ptr<Aead>> aead =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(aead.status(), IsOk());

  for (int i = 1; i < kNonceSizeInBytes + kTagSizeInBytes; i++) {
    std::string ciphertext;
    ResizeStringUninitialized(&ciphertext, i);
    EXPECT_THAT((*aead)->Decrypt(ciphertext, kAssociatedData).status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XChacha20Poly1305BoringSslTest, FailisOnFipsOnlyMode) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only ran in in FIPS-only mode";
  }

  util::SecretData key256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKey256Hex));

  EXPECT_THAT(XChacha20Poly1305BoringSsl::New(key256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

class XChacha20Poly1305BoringSslWycheproofTest
    : public TestWithParam<internal::WycheproofTestVector> {
  void SetUp() override {
    if (!internal::IsBoringSsl()) {
      GTEST_SKIP() << "Unimplemented with OpenSSL";
    }
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
    internal::WycheproofTestVector test_vector = GetParam();
    if (test_vector.key.size() != 32 ||
        test_vector.nonce.size() != kNonceSizeInBytes ||
        test_vector.tag.size() != kTagSizeInBytes) {
      GTEST_SKIP() << "Unsupported parameters: key size "
                   << test_vector.key.size()
                   << " nonce size: " << test_vector.nonce.size()
                   << " tag size: " << test_vector.tag.size();
    }
  }
};

TEST_P(XChacha20Poly1305BoringSslWycheproofTest, Decrypt) {
  internal::WycheproofTestVector test_vector = GetParam();
  util::SecretData key = util::SecretDataFromStringView(test_vector.key);
  util::StatusOr<std::unique_ptr<Aead>> cipher =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(cipher.status(), IsOk());
  std::string ciphertext =
      absl::StrCat(test_vector.nonce, test_vector.ct, test_vector.tag);
  util::StatusOr<std::string> plaintext =
      (*cipher)->Decrypt(ciphertext, test_vector.aad);
  if (plaintext.ok()) {
    EXPECT_NE(test_vector.expected, "invalid")
        << "Decrypted invalid ciphertext with ID " << test_vector.id;
    EXPECT_EQ(*plaintext, test_vector.msg)
        << "Incorrect decryption: " << test_vector.id;
  } else {
    EXPECT_THAT(test_vector.expected, Not(AllOf(Eq("valid"), Eq("acceptable"))))
        << "Could not decrypt test with tcId: " << test_vector.id
        << " iv_size: " << test_vector.nonce.size()
        << " tag_size: " << test_vector.tag.size()
        << " key_size: " << key.size() << "; error: " << plaintext.status();
  }
}

INSTANTIATE_TEST_SUITE_P(XChacha20Poly1305BoringSslWycheproofTests,
                         XChacha20Poly1305BoringSslWycheproofTest,
                         ValuesIn(internal::ReadWycheproofTestVectors(
                             /*file_name=*/"xchacha20_poly1305_test.json")));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
