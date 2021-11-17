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
#include "tink/aead/internal/ssl_aead.h"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/config/tink_fips.h"
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
using ::testing::Not;
using ::testing::Test;

constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAad = "Some data to authenticate.";
// 128 bits key.
constexpr absl::string_view k128Key = "000102030405060708090a0b0c0d0e0f";
// 256 bits key.
constexpr absl::string_view k256Key =
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
// 12 bytes IV.
constexpr absl::string_view kAesGcmIvHex = "0123456789012345678901234";
// 24 bytes IV.
constexpr absl::string_view kXchacha20Poly1305IvHex =
    "012345678901234567890123456789012345678901234567";

// Tests that encryption of `message` with `aad`, and `iv` succeeds; writes the
// result in `ciphertext_buffer`.
void DoTestEncrypt(SslOneShotAead* aead, absl::string_view message,
                   absl::string_view aad, size_t tag_size, absl::string_view iv,
                   absl::Span<char> ciphertext_buffer) {
  ASSERT_GE(ciphertext_buffer.size(), message.size() + tag_size);
  util::StatusOr<int64_t> res =
      aead->Encrypt(message, aad, iv, absl::MakeSpan(ciphertext_buffer));
  ASSERT_THAT(res.status(), IsOk());
  EXPECT_EQ(*res, message.size() + tag_size);
}

// Tests that decryption of `ciphertext_buffer` with `aad` and `iv` succeeds and
// equals `message`.
void DoTestDecrypt(SslOneShotAead* aead, absl::string_view message,
                   absl::string_view aad, absl::string_view iv,
                   absl::string_view ciphertext_buffer) {
  std::string plaintext_buff;
  subtle::ResizeStringUninitialized(&plaintext_buff, message.size());
  util::StatusOr<int64_t> written_bytes =
      aead->Decrypt(ciphertext_buffer, aad, iv, absl::MakeSpan(plaintext_buff));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, message.size());
  EXPECT_EQ(plaintext_buff, message);
}

TEST(SslOneShotAeadTest, AesGcmCiphertextPLaintextSize) {
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  EXPECT_EQ((*aead)->CiphertextSize(kMessage.size()),
            kMessage.size() + kAesGcmTagSizeInBytes);
  EXPECT_EQ((*aead)->PlaintextSize(kMessage.size() + kAesGcmTagSizeInBytes),
            kMessage.size());
  // Minimum size.
  EXPECT_EQ((*aead)->PlaintextSize(kAesGcmTagSizeInBytes), 0);
  // Smaller than the minumum.
  EXPECT_EQ((*aead)->PlaintextSize(0), 0);
}

TEST(SslOneShotAeadTest, AesGcmSivCiphertextPLaintextSize) {
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmSivOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  EXPECT_EQ((*aead)->CiphertextSize(kMessage.size()),
            kMessage.size() + kAesGcmTagSizeInBytes);
  EXPECT_EQ((*aead)->PlaintextSize(kMessage.size() + kAesGcmTagSizeInBytes),
            kMessage.size());
  // Minimum size.
  EXPECT_EQ((*aead)->PlaintextSize(kAesGcmTagSizeInBytes), 0);
  // Smaller than the minumum.
  EXPECT_EQ((*aead)->PlaintextSize(0), 0);
}

TEST(SslOneShotAeadTest, Xchacha20Poly1305CiphertextPLaintextSize) {
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateXchacha20Poly1305OneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  EXPECT_EQ((*aead)->CiphertextSize(kMessage.size()),
            kMessage.size() + kXchacha20Poly1305TagSizeInBytes);
  EXPECT_EQ((*aead)->PlaintextSize(kMessage.size() +
                                   kXchacha20Poly1305TagSizeInBytes),
            kMessage.size());
  // Minimum size.
  EXPECT_EQ((*aead)->PlaintextSize(kXchacha20Poly1305TagSizeInBytes), 0);
  // Smaller than the minumum.
  EXPECT_EQ((*aead)->PlaintextSize(0), 0);
}

TEST(SslOneShotAeadTest, AesGcmEncryptDecrypt) {
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kAesGcmIvHex);
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    (*aead)->CiphertextSize(kMessage.size()));
  DoTestEncrypt(aead->get(), kMessage, kAad, kAesGcmTagSizeInBytes, iv,
                absl::MakeSpan(ciphertext_buffer));
  DoTestDecrypt(aead->get(), kMessage, kAad, iv, ciphertext_buffer);
}

TEST(SslOneShotAeadTest, AesGcmSivEncryptDecrypt) {
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmSivOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kAesGcmIvHex);
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    (*aead)->CiphertextSize(kMessage.size()));
  DoTestEncrypt(aead->get(), kMessage, kAad, kAesGcmTagSizeInBytes, iv,
                absl::MakeSpan(ciphertext_buffer));
  DoTestDecrypt(aead->get(), kMessage, kAad, iv, ciphertext_buffer);
}

TEST(SslOneShotAeadTest, Xchacha20Poly1305EncryptDecrypt) {
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateXchacha20Poly1305OneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kXchacha20Poly1305IvHex);
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    (*aead)->CiphertextSize(kMessage.size()));
  DoTestEncrypt(aead->get(), kMessage, kAad, kXchacha20Poly1305TagSizeInBytes,
                iv, absl::MakeSpan(ciphertext_buffer));
  DoTestDecrypt(aead->get(), kMessage, kAad, iv, ciphertext_buffer);
}

// Calculates a new string with the `position`'s byte modified.
std::string ModifyString(absl::string_view input_str, int position) {
  std::string modified(input_str.data(), input_str.size());
  modified[position / 8] ^= 1 << (position % 8);
  return modified;
}

// Tests encryption/decryption with a modified ciphertext.
void DoTestEncryptDecryptWithModifiedCiphertext(SslOneShotAead* aead,
                                                size_t tag_size,
                                                absl::string_view iv) {
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    kMessage.size() + tag_size);

  util::StatusOr<int64_t> written_bytes =
      aead->Encrypt(kMessage, kAad, iv, absl::MakeSpan(ciphertext_buffer));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, kMessage.size() + tag_size);
  std::string plaintext_buffer;
  subtle::ResizeStringUninitialized(&plaintext_buffer, kMessage.size());

  // Modify the ciphertext
  for (size_t i = 0; i < ciphertext_buffer.size() * 8; i++) {
    EXPECT_THAT(aead->Decrypt(ModifyString(ciphertext_buffer, i), kAad, iv,
                              absl::MakeSpan(plaintext_buffer))
                    .status(),
                Not(IsOk()))
        << i;
  }
  // Modify the additional data
  for (size_t i = 0; i < kAad.size() * 8; i++) {
    EXPECT_THAT(aead->Decrypt(ciphertext_buffer, ModifyString(kAad, i), iv,
                              absl::MakeSpan(plaintext_buffer))
                    .status(),
                Not(IsOk()))
        << i;
  }
  // Truncate the ciphertext
  for (size_t i = 0; i < ciphertext_buffer.size(); i++) {
    std::string truncated_ct(ciphertext_buffer, 0, i);
    EXPECT_THAT(
        aead->Decrypt(truncated_ct, kAad, iv, absl::MakeSpan(plaintext_buffer))
            .status(),
        Not(IsOk()))
        << i;
  }
}

TEST(SslOneShotAeadTest, AesGcmTestModification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  DoTestEncryptDecryptWithModifiedCiphertext(
      aead->get(), kAesGcmTagSizeInBytes, absl::HexStringToBytes(kAesGcmIvHex));
}

TEST(SslOneShotAeadTest, AesGcmSivTestModification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmSivOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  DoTestEncryptDecryptWithModifiedCiphertext(
      aead->get(), kAesGcmTagSizeInBytes, absl::HexStringToBytes(kAesGcmIvHex));
}

TEST(SslOneShotAeadTest, Xchacha20Poly1305TestModification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateXchacha20Poly1305OneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  DoTestEncryptDecryptWithModifiedCiphertext(
      aead->get(), kXchacha20Poly1305TagSizeInBytes,
      absl::HexStringToBytes(kXchacha20Poly1305IvHex));
}

void TestDecryptWithEmptyAad(SslOneShotAead* aead, absl::string_view ciphertext,
                             absl::string_view iv) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  std::string plaintext_buffer;
  subtle::ResizeStringUninitialized(&plaintext_buffer, kMessage.size());
  const absl::string_view empty_aad;
  std::vector<absl::string_view> values = {empty_aad, absl::string_view(), ""};
  for (auto& aad : values) {
    DoTestDecrypt(aead, kMessage, aad, iv, ciphertext);
  }
}

void DoTestWithEmptyAad(SslOneShotAead* aead, absl::string_view iv,
                        size_t tag_size) {
  const absl::string_view empty_aad;
  std::vector<absl::string_view> values = {empty_aad, absl::string_view(), ""};
  for (auto& aad : values) {
    std::string ciphertext_buffer;
    subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                      kMessage.size() + tag_size);
    DoTestEncrypt(aead, kMessage, aad, tag_size, iv,
                  absl::MakeSpan(ciphertext_buffer));
    TestDecryptWithEmptyAad(aead, ciphertext_buffer, iv);
  }
}

TEST(SslOneShotAeadTest, AesGcmTestEmptyAad) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  DoTestWithEmptyAad(aead->get(), absl::HexStringToBytes(kAesGcmIvHex),
                     kAesGcmTagSizeInBytes);
}

TEST(SslOneShotAeadTest, AesGcmSivTestEmptyAad) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmSivOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());

  DoTestWithEmptyAad(aead->get(), absl::HexStringToBytes(kAesGcmIvHex),
                     kAesGcmTagSizeInBytes);
}

TEST(SslOneShotAeadTest, Xchacha20Poly1305TestEmptyAad) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateXchacha20Poly1305OneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  DoTestWithEmptyAad(aead->get(),
                     absl::HexStringToBytes(kXchacha20Poly1305IvHex),
                     kXchacha20Poly1305TagSizeInBytes);
}

// Tests encryption/decryption with empty, default and null message
// string_views, with `iv` and `aad`.
void DoTestEmptyMessageEncryptDecrypt(SslOneShotAead* aead,
                                      absl::string_view iv, size_t tag_size,
                                      absl::string_view aad = kAad) {
  std::string ciphertext_buffer;
  subtle::ResizeStringUninitialized(&ciphertext_buffer, tag_size);
  {  // Message is a null string_view.
    const absl::string_view message;
    DoTestEncrypt(aead, message, aad, tag_size, iv,
                  absl::MakeSpan(ciphertext_buffer));
    DoTestDecrypt(aead, "", aad, iv, ciphertext_buffer);
  }
  {  // Message is an empty string.
    const std::string message = "";
    DoTestEncrypt(aead, message, aad, tag_size, iv,
                  absl::MakeSpan(ciphertext_buffer));
    DoTestDecrypt(aead, "", aad, iv, ciphertext_buffer);
  }
  {  // Message is a default-constructed string_view.
    DoTestEncrypt(aead, absl::string_view(), aad, tag_size, iv,
                  absl::MakeSpan(ciphertext_buffer));
    DoTestDecrypt(aead, "", aad, iv, ciphertext_buffer);
  }
}

TEST(SslOneShotAeadTest, AesGcmEmptyMessage) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kAesGcmIvHex);
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, kAesGcmTagSizeInBytes);
}

TEST(SslOneShotAeadTest, AesGcmSivEmptyMessage) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmSivOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kAesGcmIvHex);
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, kAesGcmTagSizeInBytes);
}

TEST(SslOneShotAeadTest, Xchacha20Poly1305EmptyMessage) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateXchacha20Poly1305OneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kXchacha20Poly1305IvHex);
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv,
                                   kXchacha20Poly1305TagSizeInBytes);
}

TEST(SslOneShotAeadTest, AesGcmEmptyMessageAndAad) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kAesGcmIvHex);
  const absl::string_view aad_default;
  const absl::string_view aad_empty = "";
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, kAesGcmTagSizeInBytes,
                                   aad_default);
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, kAesGcmTagSizeInBytes,
                                   /*aad=*/absl::string_view());
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, kAesGcmTagSizeInBytes,
                                   aad_empty);
}

TEST(SslOneShotAeadTest, AesGcmSivEmptyMessageAndAad) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmSivOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kAesGcmIvHex);
  const absl::string_view aad_default;
  const absl::string_view aad_empty = "";
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, kAesGcmTagSizeInBytes,
                                   aad_default);
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, kAesGcmTagSizeInBytes,
                                   /*aad=*/absl::string_view());
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, kAesGcmTagSizeInBytes,
                                   aad_empty);
}

TEST(SslOneShotAeadTest, Xchacha20Poly1305EmptyMessageAndAad) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateXchacha20Poly1305OneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(kXchacha20Poly1305IvHex);
  const absl::string_view aad_default;
  const absl::string_view aad_empty = "";
  DoTestEmptyMessageEncryptDecrypt(
      aead->get(), iv, kXchacha20Poly1305TagSizeInBytes, aad_default);
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv,
                                   kXchacha20Poly1305TagSizeInBytes,
                                   /*aad=*/absl::string_view());
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv,
                                   kXchacha20Poly1305TagSizeInBytes, aad_empty);
}

TEST(SslOneShotAeadTest, AesGcmTestInvalidKeySizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  for (int keysize = 0; keysize < 65; keysize++) {
    util::SecretData key(keysize, 'x');
    util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
        CreateAesGcmOneShotCrypter(key);
    if (keysize == 16 || keysize == 32) {
      EXPECT_THAT(aead.status(), IsOk()) << "with key size " << keysize;
    } else {
      EXPECT_THAT(aead.status(), Not(IsOk())) << "with key size " << keysize;
    }
  }
}

TEST(SslOneShotAeadTest, AesGcmSivTestInvalidKeySizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  for (int keysize = 0; keysize < 65; keysize++) {
    util::SecretData key(keysize, 'x');
    util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
        CreateAesGcmSivOneShotCrypter(key);
    if (keysize == 16 || keysize == 32) {
      EXPECT_THAT(aead.status(), IsOk()) << "with key size " << keysize;
    } else {
      EXPECT_THAT(aead.status(), Not(IsOk())) << "with key size " << keysize;
    }
  }
}

TEST(SslOneShotAeadTest, Xchacha20Poly1305TestInvalidKeySizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  for (int keysize = 0; keysize < 65; keysize++) {
    util::SecretData key(keysize, 'x');
    util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
        CreateXchacha20Poly1305OneShotCrypter(key);
    if (keysize == 32) {
      EXPECT_THAT(aead.status(), IsOk()) << "with key size " << keysize;
    } else {
      EXPECT_THAT(aead.status(), Not(IsOk())) << "with key size " << keysize;
    }
  }
}

TEST(SslOneShotAeadTest, Xchacha20Poly1305TestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateXchacha20Poly1305OneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST(SslOneShotAeadTest, AesGcmTestFipsOnly) {
  if (IsFipsModeEnabled() && !FIPS_mode()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  util::SecretData key_128 =
      util::SecretDataFromStringView(absl::HexStringToBytes(k128Key));
  util::SecretData key_256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(k256Key));

  EXPECT_THAT(CreateAesGcmOneShotCrypter(key_128).status(), IsOk());
  EXPECT_THAT(CreateAesGcmOneShotCrypter(key_256).status(), IsOk());
}

TEST(SslOneShotAeadTest, AesGcmTestTestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || FIPS_mode()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::SecretData key_128 =
      util::SecretDataFromStringView(absl::HexStringToBytes(k128Key));
  util::SecretData key_256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(k256Key));

  EXPECT_THAT(CreateAesGcmOneShotCrypter(key_128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(CreateAesGcmOneShotCrypter(key_256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AesGcmSivBoringSslTest, AesGcmTestSivTestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  util::SecretData key_128 =
      util::SecretDataFromStringView(absl::HexStringToBytes(k128Key));
  util::SecretData key_256 =
      util::SecretDataFromStringView(absl::HexStringToBytes(k256Key));

  EXPECT_THAT(CreateAesGcmSivOneShotCrypter(key_128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(CreateAesGcmSivOneShotCrypter(key_256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(SslOneShotAeadTest, BufferOverlapEncryptFails) {
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());

  std::string ciphertext_buffer(kMessage.data(), kMessage.size());
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    (*aead)->CiphertextSize(kMessage.size()));

  EXPECT_THAT(
      (*aead)
          ->Encrypt(
              absl::string_view(ciphertext_buffer).substr(0, kMessage.size()),
              kAad, kAesGcmIvHex, absl::MakeSpan(ciphertext_buffer))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SslOneShotAeadTest, BufferOverlapDecryptFails) {
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CreateAesGcmOneShotCrypter(
          util::SecretDataFromStringView(absl::HexStringToBytes(k256Key)));
  ASSERT_THAT(aead.status(), IsOk());

  std::string iv = absl::HexStringToBytes(kAesGcmIvHex);
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    (*aead)->CiphertextSize(kMessage.size()));
  DoTestEncrypt(aead->get(), kMessage, kAad, kAesGcmTagSizeInBytes, iv,
                absl::MakeSpan(ciphertext_buffer));

  EXPECT_THAT(
      (*aead)
          ->Decrypt(
              ciphertext_buffer, kAad, iv,
              absl::MakeSpan(ciphertext_buffer).subspan(0, kMessage.size()))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

// TODO(ambrosin): Move wycheproof tests here.

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
