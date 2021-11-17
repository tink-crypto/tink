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

#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/types/span.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;

// TODO(b/198004452): Add test using Wycheproof vectors.
constexpr absl::string_view kKeySecret = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAad = "Some data to authenticate.";

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

// The EncodedCiphertext test verifies this constant.
constexpr absl::string_view kEncodedCiphertext =
    "22889553081aa27f0f62ed2f32b068331cb3d8103e121c8b0c898cf70b613e334b7e913323"
    "128429226950dd2f4d42a6fc";

// The MaxSizes test verifies these constants.
constexpr int64_t kMaxEncryptionSize =
    kMessage.size() + kIvSizeInBytes + kTagSizeInBytes;
// kMaxEncryptionSize - kIvSize - kTagSize.
constexpr int64_t kMaxDecryptionSize = kMessage.size();

class ZeroCopyAesGcmBoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    util::SecretData key =
        util::SecretDataFromStringView(absl::HexStringToBytes(kKeySecret));
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

TEST_F(ZeroCopyAesGcmBoringSslTest, MaxDecryptionSizeOfCiphder) {
  EXPECT_EQ(kMaxEncryptionSize, cipher_->MaxEncryptionSize(kMessage.size()));
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, kMaxEncryptionSize);
  util::StatusOr<int64_t> ciphertext_size =
      cipher_->Encrypt(kMessage, kAad, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size.status(), IsOk());
  EXPECT_EQ(kMaxDecryptionSize, cipher_->MaxDecryptionSize(*ciphertext_size));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncodedCiphertext) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMaxDecryptionSize);
  util::StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(absl::HexStringToBytes(kEncodedCiphertext), kAad,
                       absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size.status(), IsOk());
  EXPECT_EQ(plaintext.substr(0, *plaintext_size), kMessage);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncryptDecrypt) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, kMaxEncryptionSize);
  util::StatusOr<int64_t> ciphertext_size =
      cipher_->Encrypt(kMessage, kAad, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size.status(), IsOk());
  ciphertext.resize(*ciphertext_size);

  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMaxDecryptionSize);
  util::StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(ciphertext, kAad, absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size.status(), IsOk());
  EXPECT_EQ(plaintext.substr(0, *plaintext_size), kMessage);

  // Decrypt using the non zero copy library and check equivalence.
  util::SecretData key =
      util::SecretDataFromStringView(absl::HexStringToBytes(kKeySecret));
  util::StatusOr<std::unique_ptr<Aead>> non_zero_copy_cypher =
      subtle::AesGcmBoringSsl::New(key);
  ASSERT_THAT(non_zero_copy_cypher.status(), IsOk());
  util::StatusOr<std::string> plaintext_string =
      (*non_zero_copy_cypher)->Decrypt(ciphertext, kAad);
  ASSERT_THAT(plaintext_string.status(), IsOk());
  EXPECT_EQ(*plaintext_string, kMessage);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EmptyBufferEncryptDecrypt) {
  constexpr absl::string_view kEmptyPlaintext = "";
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kEmptyPlaintext.size()));
  util::StatusOr<int64_t> written_bytes =
      cipher_->Encrypt(kEmptyPlaintext, kAad, absl::MakeSpan(ciphertext));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, kIvSizeInBytes + kTagSizeInBytes);

  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, cipher_->MaxDecryptionSize(ciphertext.size()));

  written_bytes = cipher_->Decrypt(ciphertext, kAad, absl::MakeSpan(plaintext));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, 0);
  EXPECT_EQ(plaintext, "");
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EmptyBufferEmptyAadEncryptDecrypt) {
  constexpr absl::string_view kEmptyPlaintext = "";
  constexpr absl::string_view kEmptyAad = "";
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kEmptyPlaintext.size()));
  util::StatusOr<int64_t> written_bytes =
      cipher_->Encrypt(kEmptyPlaintext, kEmptyAad, absl::MakeSpan(ciphertext));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, kIvSizeInBytes + kTagSizeInBytes);

  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, cipher_->MaxDecryptionSize(ciphertext.size()));

  written_bytes =
      cipher_->Decrypt(ciphertext, kEmptyAad, absl::MakeSpan(plaintext));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, 0);
  EXPECT_EQ(plaintext, "");
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EmptyBufferNullAadEncryptDecrypt) {
  constexpr absl::string_view kEmptyPlaintext = "";
  absl::string_view empty_aad;
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kEmptyPlaintext.size()));
  util::StatusOr<int64_t> written_bytes =
      cipher_->Encrypt(kEmptyPlaintext, empty_aad, absl::MakeSpan(ciphertext));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, kIvSizeInBytes + kTagSizeInBytes);

  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, cipher_->MaxDecryptionSize(ciphertext.size()));

  written_bytes =
      cipher_->Decrypt(ciphertext, empty_aad, absl::MakeSpan(plaintext));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, 0);
  EXPECT_EQ(plaintext, "");
}

TEST_F(ZeroCopyAesGcmBoringSslTest, SmallBufferEncrypt) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, kMaxEncryptionSize - 1);
  EXPECT_EQ(cipher_->Encrypt(kMessage, kAad, absl::MakeSpan(ciphertext))
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, SmallBufferDecrypt) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMaxDecryptionSize - 1);
  EXPECT_EQ(cipher_
                ->Decrypt(absl::HexStringToBytes(kEncodedCiphertext), kAad,
                          absl::MakeSpan(plaintext))
                .status()
                .code(),
            absl::StatusCode::kInvalidArgument);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, BuffersOverlapEncrypt) {
  // Create message and ciphertext buffers that overlap by 1 character.
  std::string message_buffer(kMessage);
  int64_t message_buffer_size = message_buffer.size();
  message_buffer.resize(message_buffer_size + kMaxEncryptionSize);
  auto ciphertext_span = absl::Span<char>(
      &message_buffer[0] + message_buffer_size - 1, kMaxEncryptionSize + 1);
  message_buffer.resize(message_buffer_size);
  EXPECT_EQ(
      cipher_->Encrypt(message_buffer, kAad, ciphertext_span).status().code(),
      absl::StatusCode::kFailedPrecondition);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, BuffersOverlapDecrypt) {
  // Create ciphertext and plaintext buffers that overlap by 1 character.
  std::string ciphertext(absl::HexStringToBytes(kEncodedCiphertext));
  int64_t ciphertext_size = ciphertext.size();
  ciphertext.resize(ciphertext_size + kMaxDecryptionSize);
  auto plaintext_span = absl::Span<char>(&ciphertext[0] + ciphertext_size - 1,
                                         kMaxDecryptionSize + 1);
  ciphertext.resize(ciphertext_size);
  EXPECT_EQ(cipher_->Decrypt(ciphertext, kAad, plaintext_span).status().code(),
            absl::StatusCode::kFailedPrecondition);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, ModifiedStrings) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMaxDecryptionSize);
  std::string decoded_ciphertext = absl::HexStringToBytes(kEncodedCiphertext);

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

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
