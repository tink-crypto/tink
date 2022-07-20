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
#include "tink/internal/bn_util.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Not;

util::StatusOr<internal::SslUniquePtr<BIGNUM>> HexToBignum(
    absl::string_view bn_hex) {
  BIGNUM* bn = nullptr;
  BN_hex2bn(&bn, bn_hex.data());
  return internal::SslUniquePtr<BIGNUM>(bn);
}

TEST(BnUtil, StringToBignum) {
  std::vector<std::string> bn_str = {"0000000000000000", "0000000000000001",
                                     "1000000000000000", "ffffffffffffffff",
                                     "0fffffffffffffff", "00ffffffffffffff"};
  for (const std::string& s : bn_str) {
    const std::string bn_bytes = absl::HexStringToBytes(s);
    util::StatusOr<internal::SslUniquePtr<BIGNUM>> bn =
        StringToBignum(bn_bytes);
    ASSERT_THAT(bn, IsOk());

    util::StatusOr<internal::SslUniquePtr<BIGNUM>> expected_bn = HexToBignum(s);
    ASSERT_THAT(expected_bn, IsOk());
    EXPECT_EQ(BN_cmp(expected_bn->get(), bn->get()), 0);
  }
}

TEST(BnUtil, BignumToString) {
  std::vector<std::string> bn_strs = {"0000000000000000", "0000000000000001",
                                      "1000000000000000", "ffffffffffffffff",
                                      "0fffffffffffffff", "00ffffffffffffff"};
  for (const std::string& s : bn_strs) {
    util::StatusOr<internal::SslUniquePtr<BIGNUM>> expected_bn = HexToBignum(s);
    ASSERT_THAT(expected_bn, IsOk());

    const std::string bn_bytes = absl::HexStringToBytes(s);
    util::StatusOr<std::string> result =
        BignumToString(expected_bn->get(), bn_bytes.size());
    ASSERT_THAT(result, IsOk());
    EXPECT_EQ(bn_bytes, *result);
  }
}

TEST(BnUtil, BignumToSecretData) {
  std::vector<std::string> bn_strs = {"0000000000000000", "0000000000000001",
                                      "1000000000000000", "ffffffffffffffff",
                                      "0fffffffffffffff", "00ffffffffffffff"};
  for (const std::string& s : bn_strs) {
    util::StatusOr<internal::SslUniquePtr<BIGNUM>> expected_bn = HexToBignum(s);
    ASSERT_THAT(expected_bn, IsOk());

    const std::string bn_bytes = absl::HexStringToBytes(s);
    util::StatusOr<util::SecretData> result =
        BignumToSecretData(expected_bn->get(), bn_bytes.size());
    ASSERT_THAT(result, IsOk());
    auto result_data = absl::string_view(
        reinterpret_cast<char*>(result->data()), result->size());
    EXPECT_EQ(absl::string_view(bn_bytes), result_data);
  }
}

TEST(BnUtil, BignumToBinaryPadded) {
  std::vector<std::string> bn_strs = {"0000000000000000", "0000000000000001",
                                      "1000000000000000", "ffffffffffffffff",
                                      "0fffffffffffffff", "00ffffffffffffff"};
  for (const std::string& s : bn_strs) {
    util::StatusOr<internal::SslUniquePtr<BIGNUM>> expected_bn = HexToBignum(s);
    ASSERT_THAT(expected_bn, IsOk());

    const std::string bn_bytes = absl::HexStringToBytes(s);
    std::vector<char> buffer;
    buffer.resize(bn_bytes.size());
    util::Status res = BignumToBinaryPadded(
        absl::MakeSpan(buffer.data(), buffer.size()), expected_bn->get());
    ASSERT_THAT(res, IsOk());
    auto buffer_data = absl::string_view(buffer.data(), buffer.size());
    EXPECT_EQ(absl::string_view(bn_bytes), buffer_data);
  }
}

// Make sure that for every buffer size that is smaller than the actual BN as a
// string, we get an error.
TEST(BnUtil, BufferToSmall) {
  const std::string bn_str = "0fffffffffffffff";
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> expected_bn =
      HexToBignum(bn_str);
  ASSERT_THAT(expected_bn, IsOk());
  const std::string bn_bytes = absl::HexStringToBytes(bn_str);
  for (size_t buffer_size = 1; buffer_size < bn_bytes.size(); buffer_size++) {
    {
      std::vector<char> buffer;
      buffer.resize(buffer_size);
      util::Status result = BignumToBinaryPadded(
          absl::MakeSpan(buffer.data(), buffer.size()), expected_bn->get());
      EXPECT_THAT(result, Not(IsOk()));
    }
    {
      util::StatusOr<std::string> result =
          BignumToString(expected_bn->get(), buffer_size);
      EXPECT_THAT(result, Not(IsOk()));
    }
    {
      util::StatusOr<util::SecretData> result =
          BignumToSecretData(expected_bn->get(), buffer_size);
      EXPECT_THAT(result, Not(IsOk()));
    }
  }
}

TEST(BnUtil, CompareBignumWithWord) {
  internal::SslUniquePtr<BIGNUM> bn(BN_new());
  BN_set_word(bn.get(), /*value=*/0x0fffffffffffffffUL);
  EXPECT_EQ(CompareBignumWithWord(bn.get(), /*word=*/0x0fffffffffffffffL), 0);
  std::vector<BN_ULONG> smaller_words = {
      0x0000000000000000UL, 0x0000000000000001UL, 0x00ffffffffffffffUL};
  for (const auto& word : smaller_words) {
    EXPECT_GT(CompareBignumWithWord(bn.get(), word), 0)
        << absl::StrCat("With value: 0x", absl::Hex(word));
  }
  std::vector<BN_ULONG> larger_words = {0x1000000000000000UL,
                                        0xffffffffffffffffUL};
  for (const auto& word : larger_words) {
    EXPECT_LT(CompareBignumWithWord(bn.get(), word), 0)
        << absl::StrCat("With value: 0x", absl::Hex(word));
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
