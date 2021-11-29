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
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/internal/err_util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::AllOf;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;

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
    "22889553081aa27f0f62ed2f32b068331cb3d8103e121c8b0c898cf70b613e334b7e913323"
    "128429226950dd2f4d42a6fc";

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

TEST(ZeroCopyAesGcmBoringSslWycheproofTest, TestVectors) {
  std::vector<WycheproofTestVector> test_vectors = ReadWycheproofTestVectors(
      /*file_name=*/"aes_gcm_test.json");
  ASSERT_THAT(test_vectors, Not(IsEmpty()));
  for (const auto& test_vector : test_vectors) {
    if (test_vector.key.size() != 16 || test_vector.key.size() != 32 ||
        test_vector.nonce.size() != 12 || test_vector.tag.size() != 16) {
      continue;
    }

    util::SecretData key = util::SecretDataFromStringView(test_vector.key);
    util::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ZeroCopyAesGcmBoringSsl::New(key);
    ASSERT_THAT(cipher.status(), IsOk());

    std::string ciphertext =
        absl::StrCat(test_vector.nonce, test_vector.ct, test_vector.tag);

    std::string plaintext;
    plaintext.resize((*cipher)->MaxDecryptionSize(ciphertext.size()));
    util::StatusOr<int64_t> written_bytes = (*cipher)->Decrypt(
        ciphertext, test_vector.aad, absl::MakeSpan(plaintext));

    if (written_bytes.ok()) {
      EXPECT_NE(test_vector.expected, "invalid")
          << "Decrypted invalid ciphertext with ID " << test_vector.id;
      EXPECT_EQ(plaintext.substr(0, *written_bytes), test_vector.msg)
          << "Incorrect decryption: " << test_vector.id;
    } else {
      EXPECT_THAT(test_vector.expected,
                  Not(AllOf(Eq("valid"), Eq("acceptable"))))
          << "Could not decrypt test with tcId: " << test_vector.id
          << " iv_size: " << test_vector.nonce.size()
          << " tag_size: " << test_vector.tag.size()
          << " key_size: " << key.size()
          << "; error: " << written_bytes.status();
    }
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
