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

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
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
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/ssl_util.h"
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
using ::testing::AllOf;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

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

enum CipherType {
  kAesGcm,
  kAesGcmSiv,
  kXchacha20Poly1305,
};

struct SslOneShotAeadTestParams {
  std::string test_name;
  CipherType cipher;
  int tag_size;
  absl::string_view iv_hex;
  absl::string_view key_hex;
};

// Returns a SslOneShotAead from `cipher_name` and `key`.
util::StatusOr<std::unique_ptr<SslOneShotAead>> CipherFromName(
    CipherType cipher, const util::SecretData& key) {
  switch (cipher) {
    case CipherType::kAesGcm: {
      return CreateAesGcmOneShotCrypter(key);
    }
    case CipherType::kAesGcmSiv: {
      return CreateAesGcmSivOneShotCrypter(key);
    }
    case CipherType::kXchacha20Poly1305: {
      return CreateXchacha20Poly1305OneShotCrypter(key);
    }
  }
}

using SslOneShotAeadTest = TestWithParam<SslOneShotAeadTestParams>;

TEST_P(SslOneShotAeadTest, CiphertextPlaintextSize) {
  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());

  EXPECT_EQ((*aead)->CiphertextSize(kMessage.size()),
            kMessage.size() + test_param.tag_size);
  EXPECT_EQ((*aead)->PlaintextSize(kMessage.size() + test_param.tag_size),
            kMessage.size());
  // Minimum size.
  EXPECT_EQ((*aead)->PlaintextSize(test_param.tag_size), 0);
  // Smaller than the minumum.
  EXPECT_EQ((*aead)->PlaintextSize(0), 0);
}

// Tests that encryption of `message` with `aad`, and `iv` succeeds; writes
// the result in `ciphertext_buffer`.
void DoTestEncrypt(SslOneShotAead* aead, absl::string_view message,
                   absl::string_view aad, size_t tag_size, absl::string_view iv,
                   absl::Span<char> ciphertext_buffer) {
  ASSERT_GE(ciphertext_buffer.size(), message.size() + tag_size);
  util::StatusOr<int64_t> res =
      aead->Encrypt(message, aad, iv, absl::MakeSpan(ciphertext_buffer));
  ASSERT_THAT(res.status(), IsOk());
  EXPECT_EQ(*res, message.size() + tag_size);
}

// Tests that decryption of `ciphertext_buffer` with `aad` and `iv` succeeds
// and equals `message`.
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

TEST_P(SslOneShotAeadTest, EncryptDecrypt) {
  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());

  std::string iv = absl::HexStringToBytes(test_param.iv_hex);
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    (*aead)->CiphertextSize(kMessage.size()));
  DoTestEncrypt(aead->get(), kMessage, kAad, test_param.tag_size, iv,
                absl::MakeSpan(ciphertext_buffer));
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

TEST_P(SslOneShotAeadTest, TestModification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());

  DoTestEncryptDecryptWithModifiedCiphertext(
      aead->get(), test_param.tag_size,
      absl::HexStringToBytes(test_param.iv_hex));
}

// Make sure that the buffer passed in to the Decrypt routine is cleared if
// decryption fails.
TEST_P(SslOneShotAeadTest, TestBufferClearsIfDecryptionFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());

  const int64_t kCiphertextSize = kMessage.size() + test_param.tag_size;
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(&ciphertext_buffer, kCiphertextSize);
  std::string iv = absl::HexStringToBytes(test_param.iv_hex);
  util::StatusOr<int64_t> written_bytes =
      (*aead)->Encrypt(kMessage, kAad, iv, absl::MakeSpan(ciphertext_buffer));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, kCiphertextSize);

  std::string plaintext_buffer;
  subtle::ResizeStringUninitialized(&plaintext_buffer, kMessage.size());
  const std::string kExpectedClearedPlaintext(plaintext_buffer.size(), '\0');
  // Alter the tag.
  for (int i = kCiphertextSize - test_param.tag_size; i < kCiphertextSize;
       i++) {
    std::string modified_ciphertext = ModifyString(ciphertext_buffer, i);
    EXPECT_THAT((*aead)
                    ->Decrypt(modified_ciphertext, kAad, iv,
                              absl::MakeSpan(plaintext_buffer))
                    .status(),
                Not(IsOk()));
    EXPECT_EQ(plaintext_buffer, kExpectedClearedPlaintext);
  }
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

TEST_P(SslOneShotAeadTest, EmptyAad) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());
  DoTestWithEmptyAad(aead->get(), absl::HexStringToBytes(test_param.iv_hex),
                     test_param.tag_size);
}

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

TEST_P(SslOneShotAeadTest, EmptyMessage) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(test_param.iv_hex);
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, test_param.tag_size);
}

TEST_P(SslOneShotAeadTest, EmptyMessageAndAad) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());
  std::string iv = absl::HexStringToBytes(test_param.iv_hex);
  const absl::string_view aad_default;
  const absl::string_view aad_empty = "";
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, test_param.tag_size,
                                   aad_default);
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, test_param.tag_size,
                                   /*aad=*/absl::string_view());
  DoTestEmptyMessageEncryptDecrypt(aead->get(), iv, test_param.tag_size,
                                   aad_empty);
}

TEST_P(SslOneShotAeadTest, BufferOverlapEncryptFails) {
  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());

  std::string ciphertext_buffer(kMessage.data(), kMessage.size());
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    (*aead)->CiphertextSize(kMessage.size()));

  EXPECT_THAT(
      (*aead)
          ->Encrypt(
              absl::string_view(ciphertext_buffer).substr(0, kMessage.size()),
              kAad, test_param.iv_hex, absl::MakeSpan(ciphertext_buffer))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(SslOneShotAeadTest, BufferOverlapDecryptFails) {
  SslOneShotAeadTestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());

  std::string iv = absl::HexStringToBytes(test_param.iv_hex);
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(&ciphertext_buffer,
                                    (*aead)->CiphertextSize(kMessage.size()));
  DoTestEncrypt(aead->get(), kMessage, kAad, test_param.tag_size, iv,
                absl::MakeSpan(ciphertext_buffer));

  EXPECT_THAT(
      (*aead)
          ->Decrypt(
              ciphertext_buffer, kAad, iv,
              absl::MakeSpan(ciphertext_buffer).subspan(0, kMessage.size()))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

std::vector<SslOneShotAeadTestParams> GetSslOneShotAeadTestParams() {
  std::vector<SslOneShotAeadTestParams> params = {
      {/*test_name=*/"AesGcm256", /*cipher=*/CipherType::kAesGcm,
       /*tag_size=*/kAesGcmTagSizeInBytes,
       /*iv_hex=*/kAesGcmIvHex,
       /*key_hex=*/k256Key},
      {/*test_name=*/"AesGcm128", /*cipher=*/CipherType::kAesGcm,
       /*tag_size=*/kAesGcmTagSizeInBytes,
       /*iv_hex=*/kAesGcmIvHex,
       /*key_hex=*/k128Key}};
  if (IsBoringSsl()) {
    params.push_back({/*test_name=*/"AesGcmSiv256",
                      /*cipher=*/CipherType::kAesGcmSiv,
                      /*tag_size=*/kAesGcmTagSizeInBytes,
                      /*iv_hex=*/kAesGcmIvHex,
                      /*key_hex=*/k256Key});
    params.push_back({/*test_name=*/"AesGcmSiv128",
                      /*cipher=*/CipherType::kAesGcmSiv,
                      /*tag_size=*/kAesGcmTagSizeInBytes,
                      /*iv_hex=*/kAesGcmIvHex,
                      /*key_hex=*/k128Key});
    params.push_back({/*test_name=*/"Xchacha20Poly1305",
                      /*cipher=*/CipherType::kXchacha20Poly1305,
                      /*tag_size=*/kXchacha20Poly1305TagSizeInBytes,
                      /*iv_hex=*/kXchacha20Poly1305IvHex,
                      /*key_hex=*/k256Key});
  }
  return params;
}

INSTANTIATE_TEST_SUITE_P(
    SslOneShotAeadTests, SslOneShotAeadTest,
    testing::ValuesIn(GetSslOneShotAeadTestParams()),
    [](const TestParamInfo<SslOneShotAeadTest::ParamType>& info) {
      return info.param.test_name;
    });

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
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "AES-GCM-SIV not supported with OpenSSL";
  }
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
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "Xchacha20-Poly1305 not supported with OpenSSL";
  }
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
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "Xchacha20-Poly1305 not supported with OpenSSL";
  }
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
    GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                    "unavailable.";
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

// Parameters for SslOneShotAeadWycheproofTest.
struct SslOneShotAeadWycheproofTestParams {
  std::string test_name;
  CipherType cipher;
  int nonce_size;
  int tag_size;
  absl::flat_hash_set<int> key_sizes;
  WycheproofTestVector test_vector;
};

class SslOneShotAeadWycheproofTest
    : public TestWithParam<SslOneShotAeadWycheproofTestParams> {
 public:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
    SslOneShotAeadWycheproofTestParams params = GetParam();
    const WycheproofTestVector& test_vector = params.test_vector;

    if (!params.key_sizes.contains(test_vector.key.size()) ||
        test_vector.nonce.size() != params.nonce_size ||
        test_vector.tag.size() != params.tag_size) {
      GTEST_SKIP() << "Unsupported parameters; key size: "
                   << test_vector.key.size()
                   << " nonce size: " << test_vector.nonce.size()
                   << " tag size: " << test_vector.tag.size();
    }
  }
};

TEST_P(SslOneShotAeadWycheproofTest, Encrypt) {
  SslOneShotAeadWycheproofTestParams params = GetParam();
  const WycheproofTestVector& test_vector = params.test_vector;
  util::SecretData key = util::SecretDataFromStringView(test_vector.key);
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CipherFromName(params.cipher, key);
  ASSERT_THAT(aead.status(), IsOk());
  std::string ciphertext_and_tag =
      absl::StrCat(test_vector.ct, test_vector.tag);
  std::string ciphertext_buffer;
  subtle::ResizeStringUninitialized(
      &ciphertext_buffer, (*aead)->CiphertextSize(test_vector.msg.size()));
  util::StatusOr<int64_t> written_bytes =
      (*aead)->Encrypt(test_vector.msg, test_vector.aad, test_vector.nonce,
                       absl::MakeSpan(ciphertext_buffer));

  std::string expected_ciphertext =
      absl::StrCat(test_vector.ct, test_vector.tag);

  std::cout << test_vector.expected << "\n";

  if (test_vector.expected == "valid" || test_vector.expected == "acceptable") {
    ASSERT_THAT(written_bytes.status(), IsOk());
    EXPECT_EQ(ciphertext_buffer, expected_ciphertext);
  } else {  // invalid.
    // In this case, if the resulting ciphertext/tag are different, the
    // testcase is correct.
    if (written_bytes.ok()) {
      EXPECT_THAT(ciphertext_buffer, Not(Eq(expected_ciphertext)));
    } else {
      GTEST_SUCCEED();
    }
  }
}

TEST_P(SslOneShotAeadWycheproofTest, Decrypt) {
  SslOneShotAeadWycheproofTestParams params = GetParam();
  const WycheproofTestVector& test_vector = params.test_vector;
  util::SecretData key = util::SecretDataFromStringView(test_vector.key);
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead =
      CipherFromName(params.cipher, key);
  ASSERT_THAT(aead.status(), IsOk());
  std::string ciphertext_and_tag =
      absl::StrCat(test_vector.ct, test_vector.tag);
  std::string plaintext_buffer;
  subtle::ResizeStringUninitialized(
      &plaintext_buffer, (*aead)->PlaintextSize(ciphertext_and_tag.size()));
  util::StatusOr<int64_t> written_bytes = (*aead)->Decrypt(
      absl::StrCat(test_vector.ct, test_vector.tag), test_vector.aad,
      test_vector.nonce, absl::MakeSpan(plaintext_buffer));

  if (written_bytes.ok()) {
    EXPECT_NE(test_vector.expected, "invalid");
    EXPECT_EQ(plaintext_buffer, test_vector.msg);
  } else {
    EXPECT_THAT(test_vector.expected, Not(AllOf(Eq("valid"), Eq("acceptable"))))
        << "Could not decrypt valid/acceptable tId: " << test_vector.id
        << " iv_size: " << test_vector.nonce.size()
        << " tag_size: " << test_vector.tag.size()
        << " key_size: " << key.size() << "; error: " << written_bytes.status();
  }
}

std::vector<SslOneShotAeadWycheproofTestParams> GetWycheproofTestParams() {
  std::vector<SslOneShotAeadWycheproofTestParams> params;
  for (const WycheproofTestVector& test_vector :
       ReadWycheproofTestVectors("aes_gcm_test.json")) {
    params.push_back({/*test_name=*/"AesGcm",
                      /*cipher_name=*/CipherType::kAesGcm,
                      /*nonce_size=*/12,
                      /*tag_size=*/16,
                      /*key_sizes=*/{16, 32}, test_vector});
  }
  if (IsBoringSsl()) {
    for (const WycheproofTestVector& test_vector :
         ReadWycheproofTestVectors("aes_gcm_siv_test.json")) {
      params.push_back({/*test_name=*/"AesGcmSiv",
                        /*cipher_name=*/CipherType::kAesGcmSiv,
                        /*nonce_size=*/12,
                        /*tag_size=*/16,
                        /*key_sizes=*/{16, 32}, test_vector});
    }
    for (const WycheproofTestVector& test_vector :
         ReadWycheproofTestVectors("xchacha20_poly1305_test.json")) {
      params.push_back({/*test_name=*/"Xchacha20Poly1305",
                        /*cipher_name=*/CipherType::kXchacha20Poly1305,
                        /*nonce_size=*/24,
                        /*tag_size=*/16,
                        /*key_sizes=*/{32}, test_vector});
    }
  }
  return params;
}

INSTANTIATE_TEST_SUITE_P(
    SslOneShotAeadWycheproofTests, SslOneShotAeadWycheproofTest,
    ValuesIn(GetWycheproofTestParams()),
    [](const TestParamInfo<SslOneShotAeadWycheproofTest::ParamType>& info) {
      return absl::StrCat(info.param.test_name, "Tid",
                          info.param.test_vector.id);
    });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
