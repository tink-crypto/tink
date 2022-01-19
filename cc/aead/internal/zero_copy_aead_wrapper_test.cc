// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/internal/zero_copy_aead_wrapper.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tink/aead/internal/mock_zero_copy_aead.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::PrimitiveSet;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::Unused;

constexpr absl::string_view kPlaintext = "Some data to encrypt.";
constexpr absl::string_view kAad = "Some data to authenticate.";
constexpr absl::string_view kCiphertext = "iv:Some data to encrypt.:tag";

using ZeroCopyAeadEntry =
    crypto::tink::PrimitiveSet<ZeroCopyAead>::Entry<ZeroCopyAead>;

TEST(ZeroCopyAeadWrapperEmptyTest, Nullptr) {
  ZeroCopyAeadWrapper wrapper;
  StatusOr<std::unique_ptr<Aead>> aead_set = wrapper.Wrap(nullptr);
  EXPECT_THAT(aead_set.status(),
              StatusIs(absl::StatusCode::kInternal, HasSubstr("non-NULL")));
}

TEST(ZeroCopyAeadWrapperEmptyTest, Empty) {
  ZeroCopyAeadWrapper wrapper;
  StatusOr<std::unique_ptr<Aead>> aead_set =
      wrapper.Wrap(absl::make_unique<PrimitiveSet<ZeroCopyAead>>());
  EXPECT_THAT(aead_set.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                          HasSubstr("no primary")));
}

class ZeroCopyAeadWrapperTest : public testing::Test {
 protected:
  void SetUp() override {
    // Defines a Tink-type key.
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(OutputPrefixType::TINK);
    key_info.set_key_id(1234543);
    key_info.set_status(KeyStatusType::ENABLED);

    // Creates a new AEAD set, adds a mock AEAD corresponding to the above key,
    // and stores the set as aead_set_.
    std::unique_ptr<PrimitiveSet<ZeroCopyAead>> aead_set(
        new PrimitiveSet<ZeroCopyAead>());
    auto entry = aead_set->AddPrimitive(SetUpMockZeroCopyAead(), key_info);
    ASSERT_THAT(entry.status(), IsOk());
    ASSERT_THAT(aead_set->set_primary(*entry), IsOk());
    aead_set_ = std::move(aead_set);
  }

  // Returns an AEAD with expected return values for all its functions set via
  // EXPECT_CALL. All values are derived from constants kPlaintext, kAad, and
  // kCiphertext.
  std::unique_ptr<MockZeroCopyAead> SetUpMockZeroCopyAead() {
    auto aead = absl::make_unique<MockZeroCopyAead>();

    EXPECT_CALL(*aead, MaxEncryptionSize(kPlaintext.size()))
        .WillRepeatedly(Return(kCiphertext.size()));
    EXPECT_CALL(*aead, Encrypt(kPlaintext, kAad, _))
        .WillRepeatedly(Invoke([&](Unused, Unused, absl::Span<char> buffer) {
          memcpy(buffer.data(), kCiphertext.data(), kCiphertext.size());
          return kCiphertext.size();
        }));
    EXPECT_CALL(*aead, MaxDecryptionSize(kCiphertext.size()))
        .WillRepeatedly(Return(kPlaintext.size()));
    EXPECT_CALL(*aead, Decrypt(kCiphertext, kAad, _))
        .WillRepeatedly(Invoke([&](Unused, Unused, absl::Span<char> buffer) {
          std::memcpy(buffer.data(), kPlaintext.data(), kPlaintext.size());
          return kPlaintext.size();
        }));

    return aead;
  }

  std::unique_ptr<PrimitiveSet<ZeroCopyAead>> aead_set_;
};

TEST_F(ZeroCopyAeadWrapperTest, EncryptDecrypt) {
  ZeroCopyAeadWrapper wrapper;
  StatusOr<std::unique_ptr<Aead>> aead_set = wrapper.Wrap(std::move(aead_set_));
  ASSERT_THAT(aead_set.status(), IsOk());

  StatusOr<std::string> ciphertext = (*aead_set)->Encrypt(kPlaintext, kAad);
  ASSERT_THAT(ciphertext.status(), IsOk());
  StatusOr<std::string> plaintext = (*aead_set)->Decrypt(*ciphertext, kAad);
  ASSERT_THAT(plaintext.status(), IsOk());
  EXPECT_EQ(*plaintext, kPlaintext);
}

TEST_F(ZeroCopyAeadWrapperTest, EncryptMultipleKeys) {
  // Manually encrypt with the primary key.
  ZeroCopyAead& aead = aead_set_->get_primary()->get_primitive();
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, CryptoFormat::kNonRawPrefixSize +
                       aead.MaxEncryptionSize(kPlaintext.size()));
  StatusOr<int64_t> ciphertext_size = aead.Encrypt(
      kPlaintext, kAad,
      absl::MakeSpan(ciphertext)
          .subspan(CryptoFormat::kNonRawPrefixSize, ciphertext.size()));
  ASSERT_THAT(ciphertext_size.status(), IsOk());
  const std::string& key_id = aead_set_->get_primary()->get_identifier();
  std::memcpy(&ciphertext[0], key_id.data(), key_id.size());
  ciphertext.resize(key_id.size() + *ciphertext_size);

  // Add a second key.
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_key_id(42);
  key_info.set_status(KeyStatusType::ENABLED);
  std::unique_ptr<ZeroCopyAead> aead1 = absl::make_unique<MockZeroCopyAead>();
  ASSERT_THAT(aead_set_->AddPrimitive(std::move(aead1), key_info).status(),
              IsOk());
  ZeroCopyAeadWrapper wrapper;
  StatusOr<std::unique_ptr<Aead>> aead_set = wrapper.Wrap(std::move(aead_set_));
  ASSERT_THAT(aead_set.status(), IsOk());

  // Encrypt with the wrapped AEAD and check that the result is equal to
  // encrypting directly with the primary key.
  StatusOr<std::string> wrap_ciphertext =
      (*aead_set)->Encrypt(kPlaintext, kAad);
  ASSERT_THAT(wrap_ciphertext.status(), IsOk());
  EXPECT_EQ(*wrap_ciphertext, ciphertext);
}

TEST_F(ZeroCopyAeadWrapperTest, EncryptDecryptRawKey) {
  // Add raw key to AEAD set.
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::RAW);
  key_info.set_key_id(1234);
  key_info.set_status(KeyStatusType::ENABLED);
  auto entry = aead_set_->AddPrimitive(SetUpMockZeroCopyAead(), key_info);
  ASSERT_THAT(entry.status(), IsOk());
  ASSERT_THAT(aead_set_->set_primary(*entry), IsOk());

  // Manually encrypt with the raw key.
  util::StatusOr<const std::vector<std::unique_ptr<ZeroCopyAeadEntry>>*>
      raw_primitives = aead_set_->get_raw_primitives();
  ASSERT_THAT(raw_primitives.status(), IsOk());
  EXPECT_EQ((*raw_primitives)->size(), 1);
  ZeroCopyAead& aead = (*raw_primitives)->front()->get_primitive();
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext,
                                    aead.MaxEncryptionSize(kPlaintext.size()));
  util::StatusOr<int64_t> ciphertext_size =
      aead.Encrypt(kPlaintext, kAad, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size.status(), IsOk());
  ciphertext.resize(*ciphertext_size);

  // Encrypt with the wrapped AEAD and check that the result is equal to
  // encrypting directly with the raw key.
  ZeroCopyAeadWrapper wrapper;
  StatusOr<std::unique_ptr<Aead>> aead_set = wrapper.Wrap(std::move(aead_set_));
  ASSERT_THAT(aead_set.status(), IsOk());
  StatusOr<std::string> wrap_ciphertext =
      (*aead_set)->Encrypt(kPlaintext, kAad);
  ASSERT_THAT(wrap_ciphertext.status(), IsOk());
  EXPECT_EQ(*wrap_ciphertext, ciphertext);

  // Manually decrypt with the raw key.
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext,
                                    aead.MaxDecryptionSize(ciphertext.size()));
  util::StatusOr<int64_t> plaintext_size =
      aead.Decrypt(ciphertext, kAad, absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size.status(), IsOk());
  plaintext.resize(*plaintext_size);
  EXPECT_EQ(plaintext, kPlaintext);

  // Decrypt with the wrapped AEAD.
  StatusOr<std::string> wrap_plaintext = (*aead_set)->Decrypt(ciphertext, kAad);
  ASSERT_THAT(wrap_plaintext.status(), IsOk());
  EXPECT_EQ(*wrap_plaintext, kPlaintext);
}

TEST_F(ZeroCopyAeadWrapperTest, EncryptBadDecrypt) {
  ZeroCopyAeadWrapper wrapper;
  StatusOr<std::unique_ptr<Aead>> aead_set = wrapper.Wrap(std::move(aead_set_));
  ASSERT_THAT(aead_set.status(), IsOk());

  StatusOr<std::string> plaintext =
      (*aead_set)->Decrypt("some bad ciphertext", kAad);
  EXPECT_EQ(plaintext.status().code(), absl::StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
