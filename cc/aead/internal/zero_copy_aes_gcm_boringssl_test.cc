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

#include "tink/aead/internal/zero_copy_aes_gcm_boringssl.h"

#include <algorithm>
#include <cstring>
#include <iterator>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/types/span.h"
#include "tink/subtle/subtle_util.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;

constexpr absl::string_view kKey128Hex = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAdditionalData = "Some data to authenticate.";

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

// The MaxSizes test verifies these constants.
constexpr int64_t kMaxEncryptionSize =
    kMessage.size() + kIvSizeInBytes + kTagSizeInBytes;
// kMaxEncryptionSize - kIvSize - kTagSize.
constexpr int64_t kMaxDecryptionSize = kMessage.size();

// Encoded ciphertext of kMessage with kAdditionalData and kKey128Hex.
constexpr absl::string_view kEncodedCiphertext =
    "b123458852bdfb78ad0c1f962156cde8bd12da1ae3e9627daa422acc7ebd7d80644f1377cb"
    "7b3f85a6cea22387eb0f3433";

class ZeroCopyAesGcmBoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    util::SecretData key =
        util::SecretDataFromStringView(absl::HexStringToBytes(kKey128Hex));
    util::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ZeroCopyAesGcmBoringSsl::New(key);
    ASSERT_THAT(cipher.status(), IsOk());
    cipher_ = std::move(*cipher);
  }

  std::unique_ptr<ZeroCopyAead> cipher_;
};

TEST_F(ZeroCopyAesGcmBoringSslTest,
       MaxDecryptionSizeOfMaxEncryptionSizeOfMessageIsMessageSize) {
  // Check i == MaxDecryptionSize(MaxEncryptionSize(i)).
  EXPECT_EQ(kMessage.size(), cipher_->MaxDecryptionSize(
                                 cipher_->MaxEncryptionSize(kMessage.size())));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncryptDecrypt) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kMessage.size()));
  util::StatusOr<int64_t> ciphertext_size =
      cipher_->Encrypt(kMessage, kAdditionalData, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size.status(), IsOk());
  EXPECT_EQ(*ciphertext_size,
            kIvSizeInBytes + kMessage.size() + kTagSizeInBytes);
  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, cipher_->MaxDecryptionSize(ciphertext.size()));
  util::StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(ciphertext, kAdditionalData, absl::MakeSpan(plaintext));

  ASSERT_THAT(plaintext_size.status(), IsOk());
  EXPECT_EQ(plaintext, kMessage);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, DecryptEncodedCiphertext) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMaxDecryptionSize);
  util::StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(absl::HexStringToBytes(kEncodedCiphertext),
                       kAdditionalData, absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size.status(), IsOk());
  EXPECT_EQ(plaintext.substr(0, *plaintext_size), kMessage);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncryptBufferTooSmall) {
  const int64_t kMaxEncryptionSize =
      kMessage.size() + kIvSizeInBytes + kTagSizeInBytes;
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, kMaxEncryptionSize - 1);
  EXPECT_THAT(
      cipher_->Encrypt(kMessage, kAdditionalData, absl::MakeSpan(ciphertext))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, DecryptBufferTooSmall) {
  const int64_t kMaxDecryptionSize = kMessage.size();
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMaxDecryptionSize - 1);
  EXPECT_THAT(cipher_
                  ->Decrypt(absl::HexStringToBytes(kEncodedCiphertext),
                            kAdditionalData, absl::MakeSpan(plaintext))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncryptOverlappingPlaintextCiphertext) {
  std::string buffer(1024, '\0');
  // Copy the kMessage at the beginning of the buffer.
  std::copy(kMessage.begin(), kMessage.end(), std::back_inserter(buffer));
  auto plaintext = absl::string_view(buffer).substr(0, kMessage.size());
  // The output buffer overlaps with a portion of the plaintext, in particular
  // the last kIvSizeInBytes bytes.
  auto cipher_buff =
      absl::MakeSpan(buffer).subspan(kMessage.size() - kIvSizeInBytes);
  EXPECT_THAT(
      cipher_->Encrypt(plaintext, kAdditionalData, cipher_buff).status(),
      StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, DecryptOverlappingPlaintextCiphertext) {
  std::string buffer(1024, '\0');
  // Plaintext's buffer starts at the beginning of the buffer.
  auto out_buffer = absl::MakeSpan(buffer).subspan(0, kMessage.size());
  std::string ciphertext_data = absl::HexStringToBytes(kEncodedCiphertext);
  // Copy the ciphertext into buffer such that the IV part will overlap with the
  // end of the plaintext output buffer.
  int ciphertext_start = kMessage.size() - kIvSizeInBytes;
  memcpy(&buffer[0] + ciphertext_start, ciphertext_data.data(),
         ciphertext_data.size());
  auto ciphertext = absl::string_view(buffer).substr(ciphertext_start,
                                                     ciphertext_data.size());
  EXPECT_THAT(
      cipher_->Decrypt(ciphertext, kAdditionalData, out_buffer).status(),
      StatusIs(absl::StatusCode::kFailedPrecondition));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
