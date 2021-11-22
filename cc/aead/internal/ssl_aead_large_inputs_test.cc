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
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/config/tink_fips.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

// We test SslOneShotAead implementations against a very large input.
namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::TestWithParam;

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

bool IsBoringSsl() {
#ifdef OPENSSL_IS_BORINGSSL
  return true;
#else
  return false;
#endif
}

struct TestParams {
  std::string test_name;
  std::string cipher;
  int tag_size;
  absl::string_view iv_hex;
  absl::string_view key_hex;
};

// Returns a SslOneShotAead from `cipher_name` and `key`.
util::StatusOr<std::unique_ptr<SslOneShotAead>> CipherFromName(
    absl::string_view cipher, const util::SecretData& key) {
  if (cipher == "aes_gcm") {
    return CreateAesGcmOneShotCrypter(key);
  }
  if (cipher == "aes_gcm_siv") {
    return CreateAesGcmSivOneShotCrypter(key);
  }
  if (cipher == "xchacha20_poly1305") {
    return CreateXchacha20Poly1305OneShotCrypter(key);
  }
  return util::Status(absl::StatusCode::kInvalidArgument,
                      absl::StrCat("Invalid cipher ", cipher));
}

using SslOneShotAeadLargeInputsTest = TestWithParam<TestParams>;

// Encrypt/decrypt with an input larger than a MAX int.
TEST_P(SslOneShotAeadLargeInputsTest, EncryptDecryptLargeInput) {
  const int64_t buff_size =
      static_cast<int64_t>(std::numeric_limits<int>::max()) + 1024;
  std::string large_input(buff_size, '0');

  TestParams test_param = GetParam();
  util::StatusOr<std::unique_ptr<SslOneShotAead>> aead = CipherFromName(
      test_param.cipher, util::SecretDataFromStringView(
                             absl::HexStringToBytes(test_param.key_hex)));
  ASSERT_THAT(aead.status(), IsOk());

  std::string iv = absl::HexStringToBytes(test_param.iv_hex);
  std::string ciphertext_buffer;
  // Length of the message + tag.
  subtle::ResizeStringUninitialized(
      &ciphertext_buffer, (*aead)->CiphertextSize(large_input.size()));

  // Encrypt.
  ASSERT_GE(ciphertext_buffer.size(), large_input.size() + test_param.tag_size);
  util::StatusOr<int64_t> res = (*aead)->Encrypt(
      large_input, kAad, iv, absl::MakeSpan(ciphertext_buffer));
  ASSERT_THAT(res.status(), IsOk());
  EXPECT_EQ(*res, large_input.size() + test_param.tag_size);

  // Decrypt.
  std::string plaintext_buff;
  subtle::ResizeStringUninitialized(&plaintext_buff, large_input.size());
  util::StatusOr<int64_t> written_bytes = (*aead)->Decrypt(
      ciphertext_buffer, kAad, iv, absl::MakeSpan(plaintext_buff));
  ASSERT_THAT(written_bytes.status(), IsOk());
  EXPECT_EQ(*written_bytes, large_input.size());
  EXPECT_EQ(plaintext_buff, large_input);
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params = {
      {/*test_name=*/"AesGcm256", /*cipher=*/"aes_gcm",
       /*tag_size=*/kAesGcmTagSizeInBytes,
       /*iv_hex=*/kAesGcmIvHex,
       /*key_hex=*/k256Key},
      {/*test_name=*/"AesGcm128", /*cipher=*/"aes_gcm",
       /*tag_size=*/kAesGcmTagSizeInBytes,
       /*iv_hex=*/kAesGcmIvHex,
       /*key_hex=*/k128Key}};
  if (IsBoringSsl()) {
    params.push_back({/*test_name=*/"AesGcmSiv256", /*cipher=*/"aes_gcm_siv",
                      /*tag_size=*/kAesGcmTagSizeInBytes,
                      /*iv_hex=*/kAesGcmIvHex,
                      /*key_hex=*/k256Key});
    params.push_back({/*test_name=*/"AesGcmSiv128", /*cipher=*/"aes_gcm_siv",
                      /*tag_size=*/kAesGcmTagSizeInBytes,
                      /*iv_hex=*/kAesGcmIvHex,
                      /*key_hex=*/k128Key});
    params.push_back({/*test_name=*/"Xchacha20Poly1305",
                      /*cipher=*/"xchacha20_poly1305",
                      /*tag_size=*/kXchacha20Poly1305TagSizeInBytes,
                      /*iv_hex=*/kXchacha20Poly1305IvHex,
                      /*key_hex=*/k256Key});
  }
  return params;
}

INSTANTIATE_TEST_SUITE_P(
    SslOneShotAeadLargeInputsTests, SslOneShotAeadLargeInputsTest,
    testing::ValuesIn(GetTestParams()),
    [](const testing::TestParamInfo<SslOneShotAeadLargeInputsTest::ParamType>&
           info) { return info.param.test_name; });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
