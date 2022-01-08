// Copyright 2021 Google LLC
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
#include "tink/internal/aes_util.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;
using ::testing::Not;

struct NistAesCtrTestVector {
  std::string iv;
  std::string key;
  std::string plaintext;
  std::string ciphertext;
};

class AesCtrTest : public testing::Test {
 protected:
  AesCtrTest() : aes_key_(util::MakeSecretUniquePtr<AES_KEY>()) {}

  void SetUp() override {
    ASSERT_EQ(AES_set_encrypt_key(
                  reinterpret_cast<const uint8_t*>(test_vector_.key.data()),
                  /*bits=*/test_vector_.key.size() * 8, aes_key_.get()),
              0);
  }

  // Test vector from NIST SP 800-38A.
  NistAesCtrTestVector test_vector_ = {
      /*iv=*/absl::HexStringToBytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
      /*key=*/absl::HexStringToBytes("2b7e151628aed2a6abf7158809cf4f3c"),
      /*plaintext=*/
      absl::HexStringToBytes(
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c8"
          "1c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
      /*ciphertext=*/
      absl::HexStringToBytes(
          "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4"
          "df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"),
  };
  const util::SecretUniquePtr<AES_KEY> aes_key_;
};

// Check that AesCtr128Crypt fails when out buffer is too small.
TEST_F(AesCtrTest, AesCtrInvalidOutSize) {
  std::string out;
  for (int size = 0; size < test_vector_.plaintext.size(); size++) {
    subtle::ResizeStringUninitialized(&out, size);
    EXPECT_THAT(AesCtr128Crypt(test_vector_.plaintext,
                               reinterpret_cast<uint8_t*>(&test_vector_.iv[0]),
                               aes_key_.get(), absl::MakeSpan(out)),
                Not(IsOk()));
  }
}

// Partial overlap of buffers of the right size is not allowed.
TEST_F(AesCtrTest, AesCtrPartiallyOverlappingFails) {
  std::string out;
  subtle::ResizeStringUninitialized(&out, 2 * test_vector_.plaintext.size());
  const int kStartIndex = test_vector_.plaintext.size() / 2;
  std::copy(test_vector_.plaintext.begin(), test_vector_.plaintext.end(),
            out.begin() + kStartIndex);
  auto plaintext =
      absl::string_view(out).substr(kStartIndex, test_vector_.plaintext.size());
  util::Status res = AesCtr128Crypt(
      plaintext, reinterpret_cast<uint8_t*>(&test_vector_.iv[0]),
      aes_key_.get(), absl::MakeSpan(out).subspan(0, plaintext.size()));
  // Checking the message to disambiguate from the kInvalidArgumentError that is
  // returned in case of wrong size of the output buffer.
  EXPECT_THAT(
      res, StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("overlap")));
  res = AesCtr128Crypt(
      plaintext, reinterpret_cast<uint8_t*>(&test_vector_.iv[0]),
      aes_key_.get(),
      absl::MakeSpan(out).subspan(plaintext.size(), plaintext.size()));
  EXPECT_THAT(
      res, StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("overlap")));
}

TEST_F(AesCtrTest, AesCtrEncrypt) {
  std::string out;
  subtle::ResizeStringUninitialized(&out, test_vector_.plaintext.size());
  ASSERT_THAT(AesCtr128Crypt(test_vector_.plaintext,
                             reinterpret_cast<uint8_t*>(&test_vector_.iv[0]),
                             aes_key_.get(), absl::MakeSpan(out)),
              IsOk());
  EXPECT_EQ(out, test_vector_.ciphertext);
}

TEST_F(AesCtrTest, AesCtrEncryptInPlace) {
  std::string inout = test_vector_.plaintext;
  ASSERT_THAT(
      AesCtr128Crypt(inout, reinterpret_cast<uint8_t*>(&test_vector_.iv[0]),
                     aes_key_.get(), absl::MakeSpan(inout)),
      IsOk());
  EXPECT_EQ(inout, test_vector_.ciphertext);
}

TEST_F(AesCtrTest, AesCtrDecrypt) {
  std::string out;
  subtle::ResizeStringUninitialized(&out, test_vector_.ciphertext.size());
  ASSERT_THAT(AesCtr128Crypt(test_vector_.ciphertext,
                             reinterpret_cast<uint8_t*>(&test_vector_.iv[0]),
                             aes_key_.get(), absl::MakeSpan(out)),
              IsOk());
  EXPECT_EQ(out, test_vector_.plaintext);
}

TEST_F(AesCtrTest, AesCtrDecryptInPlace) {
  std::string inout = test_vector_.ciphertext;
  ASSERT_THAT(
      AesCtr128Crypt(inout, reinterpret_cast<uint8_t*>(&test_vector_.iv[0]),
                     aes_key_.get(), absl::MakeSpan(inout)),
      IsOk());
  EXPECT_EQ(inout, test_vector_.plaintext);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
