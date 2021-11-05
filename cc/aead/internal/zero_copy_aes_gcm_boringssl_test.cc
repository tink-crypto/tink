// Copyright 2021 Google LLC.
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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/span.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;

// TODO(b/198004452): Add test using Wycheproof vectors.

constexpr absl::string_view kKeySecret = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAad = "Some data to authenticate.";

// The MaxSizes test verifies these constants.
constexpr int64_t max_encryption_size = 49;
constexpr int64_t max_decryption_size = 37;

// The EncodedCiphertext test verifies this constant.
constexpr absl::string_view encoded_ciphertext =
    "22889553081aa27f0f62ed2f32b068331cb3d8103e121c8b0c898cf70b613e334b7e913323"
    "128429226950dd2f4d42a6fc";

class ZeroCopyAesGcmBoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    util::SecretData key =
        util::SecretDataFromStringView(test::HexDecodeOrDie(kKeySecret));
    StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ZeroCopyAesGcmBoringSsl::New(key);
    ASSERT_THAT(cipher.status(), IsOk());
    cipher_ = std::move(*cipher);
  }

  std::unique_ptr<ZeroCopyAead> cipher_;
};

TEST_F(ZeroCopyAesGcmBoringSslTest, MaxSizes) {
  EXPECT_EQ(max_encryption_size, cipher_->MaxEncryptionSize(kMessage.size()));
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, max_encryption_size);
  StatusOr<int64_t> ciphertext_size =
      cipher_->Encrypt(kMessage, kAad, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size.status(), IsOk());
  EXPECT_EQ(max_decryption_size, cipher_->MaxDecryptionSize(*ciphertext_size));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncodedCiphertext) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, max_decryption_size);
  StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(test::HexDecodeOrDie(encoded_ciphertext), kAad,
                       absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size.status(), IsOk());
  EXPECT_EQ(plaintext.substr(0, *plaintext_size), kMessage);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncryptDecrypt) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, max_encryption_size);
  StatusOr<int64_t> ciphertext_size =
      cipher_->Encrypt(kMessage, kAad, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size.status(), IsOk());
  ciphertext.resize(*ciphertext_size);

  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, max_decryption_size);
  StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(ciphertext, kAad, absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size.status(), IsOk());
  EXPECT_EQ(plaintext.substr(0, *plaintext_size), kMessage);

  // Decrypt using the non zero copy library and check equivalence.
  util::SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKeySecret));
  StatusOr<std::unique_ptr<Aead>> non_zero_copy_cypher =
      subtle::AesGcmBoringSsl::New(key);
  ASSERT_THAT(non_zero_copy_cypher.status(), IsOk());
  StatusOr<std::string> plaintext_string =
      (*non_zero_copy_cypher)->Decrypt(ciphertext, kAad);
  ASSERT_THAT(plaintext_string.status(), IsOk());
  EXPECT_EQ(*plaintext_string, kMessage);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, SmallBufferEncrypt) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, max_encryption_size - 1);
  EXPECT_EQ(cipher_->Encrypt(kMessage, kAad, absl::MakeSpan(ciphertext))
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, SmallBufferDecrypt) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, max_decryption_size - 1);
  EXPECT_EQ(cipher_
                ->Decrypt(test::HexDecodeOrDie(encoded_ciphertext), kAad,
                          absl::MakeSpan(plaintext))
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, BuffersOverlapEncrypt) {
  // Create message and ciphertext buffers that overlap by 1 character.
  std::string message_buffer(kMessage);
  int64_t message_buffer_size = message_buffer.size();
  message_buffer.resize(message_buffer_size + max_encryption_size);
  auto ciphertext_span = absl::Span<char>(
      &message_buffer[0] + message_buffer_size - 1, max_encryption_size + 1);
  message_buffer.resize(message_buffer_size);
  EXPECT_EQ(cipher_->Encrypt(message_buffer, kAad, ciphertext_span)
                .status()
                .error_code(),
            util::error::FAILED_PRECONDITION);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, BuffersOverlapDecrypt) {
  // Create ciphertext and plaintext buffers that overlap by 1 character.
  std::string ciphertext(test::HexDecodeOrDie(encoded_ciphertext));
  int64_t ciphertext_size = ciphertext.size();
  ciphertext.resize(ciphertext_size + max_decryption_size);
  auto plaintext_span = absl::Span<char>(&ciphertext[0] + ciphertext_size - 1,
                                         max_decryption_size + 1);
  ciphertext.resize(ciphertext_size);
  EXPECT_EQ(
      cipher_->Decrypt(ciphertext, kAad, plaintext_span).status().error_code(),
      util::error::FAILED_PRECONDITION);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, ModifiedStrings) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, max_decryption_size);
  std::string decoded_ciphertext = test::HexDecodeOrDie(encoded_ciphertext);

  // Modify the ciphertext.
  std::string ciphertext_modified(decoded_ciphertext);
  ciphertext_modified[decoded_ciphertext.size() / 2] ^= 1;
  ASSERT_NE(decoded_ciphertext, ciphertext_modified);
  EXPECT_EQ(
      cipher_->Decrypt(ciphertext_modified, kAad, absl::MakeSpan(plaintext))
          .status()
          .code(),
      absl::StatusCode::kInternal);

  // Truncate the ciphertext.
  std::string ciphertext_truncated(decoded_ciphertext, 0,
                                   decoded_ciphertext.size() - 1);
  ASSERT_NE(decoded_ciphertext, ciphertext_truncated);
  EXPECT_EQ(
      cipher_->Decrypt(ciphertext_truncated, kAad, absl::MakeSpan(plaintext))
          .status()
          .code(),
      absl::StatusCode::kInternal);

  // Modify the additional data.
  std::string aad_modified = std::string(kAad);
  aad_modified[kAad.size() / 2] ^= 1;
  ASSERT_NE(kAad, aad_modified);
  EXPECT_EQ(
      cipher_
          ->Decrypt(decoded_ciphertext, aad_modified, absl::MakeSpan(plaintext))
          .status()
          .code(),
      absl::StatusCode::kInternal);
}

TEST(BuffersOverlapTest, Empty) {
  absl::string_view empty = "";
  ASSERT_FALSE(ZeroCopyAesGcmBoringSsl::BuffersOverlap(empty, empty));
  ASSERT_FALSE(ZeroCopyAesGcmBoringSsl::BuffersOverlap(empty, ""));
}

TEST(BuffersOverlapTest, Separate) {
  absl::string_view first = "first";
  absl::string_view second = "second";
  ASSERT_FALSE(ZeroCopyAesGcmBoringSsl::BuffersOverlap(first, second));
  ASSERT_TRUE(ZeroCopyAesGcmBoringSsl::BuffersOverlap(first, first));
}

TEST(BuffersOverlapTest, Overlap) {
  absl::string_view long_buffer = "a long buffer with \n several \n newlines";

  ASSERT_TRUE(
      ZeroCopyAesGcmBoringSsl::BuffersOverlap(long_buffer, long_buffer));

  ASSERT_TRUE(ZeroCopyAesGcmBoringSsl::BuffersOverlap(
      long_buffer.substr(0, 10), long_buffer.substr(9, 5)));
  ASSERT_FALSE(ZeroCopyAesGcmBoringSsl::BuffersOverlap(
      long_buffer.substr(0, 10), long_buffer.substr(10, 5)));

  ASSERT_TRUE(ZeroCopyAesGcmBoringSsl::BuffersOverlap(
      long_buffer.substr(9, 5), long_buffer.substr(0, 10)));
  ASSERT_FALSE(ZeroCopyAesGcmBoringSsl::BuffersOverlap(
      long_buffer.substr(10, 5), long_buffer.substr(0, 10)));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
