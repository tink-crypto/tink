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
#include "tink/aead/internal/aead_from_zero_copy.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/mock_zero_copy_aead.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr absl::string_view kPlaintext = "Some data to encrypt.";
constexpr absl::string_view kAssociatedData = "Some associated data.";
constexpr absl::string_view kCiphertext = "37ajhgdahjsdg8653821218236182631";

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::Unused;

TEST(AeadFromZeroCopyTest, EncryptSucceeds) {
  std::unique_ptr<MockZeroCopyAead> mock_zero_copy_aead =
      absl::WrapUnique(new MockZeroCopyAead());
  EXPECT_CALL(*mock_zero_copy_aead, MaxEncryptionSize(kPlaintext.size()))
      .WillOnce(Return(kCiphertext.size()));
  EXPECT_CALL(*mock_zero_copy_aead, Encrypt(kPlaintext, kAssociatedData, _))
      .WillOnce(Invoke([&](Unused, Unused, absl::Span<char> buffer) {
        memcpy(buffer.data(), kCiphertext.data(), kCiphertext.size());
        return kCiphertext.size();
      }));

  AeadFromZeroCopy aead(std::move(mock_zero_copy_aead));
  StatusOr<std::string> ciphertext = aead.Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext.status(), IsOk());
  EXPECT_EQ(*ciphertext, kCiphertext);
}

TEST(AeadFromZeroCopyTest, EncryptFailsIfZeroCopyEncryptFails) {
  std::unique_ptr<MockZeroCopyAead> mock_zero_copy_aead =
      absl::WrapUnique(new MockZeroCopyAead());
  EXPECT_CALL(*mock_zero_copy_aead, MaxEncryptionSize(kPlaintext.size()))
      .WillOnce(Return(kCiphertext.size()));
  EXPECT_CALL(*mock_zero_copy_aead, Encrypt(kPlaintext, kAssociatedData, _))
      .WillOnce(
          Return(Status(absl::StatusCode::kInternal, "Some error happened!")));
  AeadFromZeroCopy aead(std::move(mock_zero_copy_aead));
  EXPECT_THAT(aead.Encrypt(kPlaintext, kAssociatedData).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AeadFromZeroCopyTest, DecryptSucceeds) {
  std::unique_ptr<MockZeroCopyAead> mock_zero_copy_aead =
      absl::WrapUnique(new MockZeroCopyAead());
  EXPECT_CALL(*mock_zero_copy_aead, MaxDecryptionSize(kCiphertext.size()))
      .WillOnce(Return(kPlaintext.size()));
  EXPECT_CALL(*mock_zero_copy_aead, Decrypt(kCiphertext, kAssociatedData, _))
      .WillOnce(Invoke([&](Unused, Unused, absl::Span<char> buffer) {
        memcpy(buffer.data(), kPlaintext.data(), kPlaintext.size());
        return kPlaintext.size();
      }));

  AeadFromZeroCopy aead(std::move(mock_zero_copy_aead));
  StatusOr<std::string> plaintext = aead.Decrypt(kCiphertext, kAssociatedData);
  ASSERT_THAT(plaintext.status(), IsOk());
  EXPECT_EQ(*plaintext, kPlaintext);
}

TEST(AeadFromZeroCopyTest, EncryptFailsIfZeroCopyDecryptFails) {
  std::unique_ptr<MockZeroCopyAead> mock_zero_copy_aead =
      absl::WrapUnique(new MockZeroCopyAead());
  EXPECT_CALL(*mock_zero_copy_aead, MaxDecryptionSize(kCiphertext.size()))
      .WillOnce(Return(kPlaintext.size()));
  EXPECT_CALL(*mock_zero_copy_aead, Decrypt(kCiphertext, kAssociatedData, _))
      .WillOnce(
          Return(Status(absl::StatusCode::kInternal, "Some error happened!")));
  AeadFromZeroCopy aead(std::move(mock_zero_copy_aead));
  EXPECT_THAT(aead.Decrypt(kCiphertext, kAssociatedData).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
