// Copyright 2018 Google Inc.
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

#include "tink/daead/aes_siv_key_manager.h"

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/deterministic_aead.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_siv.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesSivKey;
using ::google::crypto::tink::AesSivKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Ne;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(AesSivKeyManagerTest, Basics) {
  EXPECT_THAT(AesSivKeyManager().get_version(), Eq(0));
  EXPECT_THAT(AesSivKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.AesSivKey"));
  EXPECT_THAT(AesSivKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesSivKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(AesSivKeyManager().ValidateKey(AesSivKey()), Not(IsOk()));
}

TEST(AesSivKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(AesSivKeyManager().ValidateKeyFormat(AesSivKeyFormat()),
              Not(IsOk()));
}

TEST(AesSivKeyManagerTest, ValidKeyFormat) {
  AesSivKeyFormat format;
  format.set_key_size(64);
  EXPECT_THAT(AesSivKeyManager().ValidateKeyFormat(format), IsOk());
}

TEST(AesSivKeyManagerTest, ValidateKeyFormatWithWrongSizes) {
  AesSivKeyFormat format;

  for (int i = 0; i < 64; ++i) {
    format.set_key_size(i);
    EXPECT_THAT(AesSivKeyManager().ValidateKeyFormat(format), Not(IsOk()))
        << " for length " << i;
  }
  for (int i = 65; i <= 200; ++i) {
    format.set_key_size(i);
    EXPECT_THAT(AesSivKeyManager().ValidateKeyFormat(format), Not(IsOk()))
        << " for length " << i;
  }
}

TEST(AesSivKeyManagerTest, CreateKey) {
  AesSivKeyFormat format;
  format.set_key_size(64);
  auto key_or = AesSivKeyManager().CreateKey(format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(), SizeIs(format.key_size()));
  EXPECT_THAT(key_or.value().version(), Eq(0));
}

TEST(AesSivKeyManagerTest, CreateKeyIsValid) {
  AesSivKeyFormat format;
  format.set_key_size(64);
  auto key_or = AesSivKeyManager().CreateKey(format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(AesSivKeyManager().ValidateKey(key_or.value()), IsOk());
}

TEST(AesSivKeyManagerTest, MultipleCreateCallsCreateDifferentKeys) {
  AesSivKeyFormat format;
  AesSivKeyManager manager;
  format.set_key_size(64);
  auto key1_or = manager.CreateKey(format);
  ASSERT_THAT(key1_or, IsOk());
  auto key2_or = manager.CreateKey(format);
  ASSERT_THAT(key2_or, IsOk());
  EXPECT_THAT(key1_or.value().key_value(), Ne(key2_or.value().key_value()));
}

TEST(AesSivKeyManagerTest, DeriveKey) {
  util::IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")};
  AesSivKeyFormat format;
  format.set_key_size(64);
  format.set_version(0);
  auto key_or = AesSivKeyManager().DeriveKey(format, &input_stream);

  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().key_value(), SizeIs(64));
  EXPECT_THAT(key_or.value().version(), Eq(0));
}

TEST(AesSivKeyManagerTest, DeriveKeyFromLongSeed) {
  util::IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefXXXXX")};

  AesSivKeyFormat format;
  format.set_key_size(64);
  format.set_version(0);
  auto key_or = AesSivKeyManager().DeriveKey(format, &input_stream);

  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(
      key_or.value().key_value(),
      Eq("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

TEST(AesSivKeyManagerTest, DeriveKeyWithoutEnoughEntropy) {
  AesSivKeyFormat format;
  format.set_key_size(64);
  format.set_version(0);
  util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};
  auto key_or = AesSivKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key_or.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("pseudorandomness")));
}

TEST(AesSivKeyManagerTest, DeriveKeyWrongVersion) {
  util::IstreamInputStream input_stream{absl::make_unique<std::stringstream>(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")};
  AesSivKeyFormat format;
  format.set_key_size(64);
  format.set_version(1);
  auto key_or = AesSivKeyManager().DeriveKey(format, &input_stream);

  ASSERT_THAT(key_or.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("version")));
}

TEST(AesSivKeyManagerTest, ValidateKey) {
  AesSivKey key;
  *key.mutable_key_value() = std::string(64, 'a');
  key.set_version(0);
  EXPECT_THAT(AesSivKeyManager().ValidateKey(key), IsOk());
}

TEST(AesSivKeyManagerTest, ValidateKeyStringLength) {
  AesSivKey key;
    key.set_version(0);
  for (int i = 0 ; i < 64; ++i) {
    *key.mutable_key_value() = std::string(i, 'a');
    EXPECT_THAT(AesSivKeyManager().ValidateKey(key), Not(IsOk()));
  }
  for (int i = 65 ; i <= 200; ++i) {
    *key.mutable_key_value() = std::string(i, 'a');
    EXPECT_THAT(AesSivKeyManager().ValidateKey(key), Not(IsOk()));
  }
}

TEST(AesSivKeyManagerTest, ValidateKeyVersion) {
  AesSivKey key;
  *key.mutable_key_value() = std::string(64, 'a');
  key.set_version(1);
  EXPECT_THAT(AesSivKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(AesSivKeyManagerTest, GetPrimitive) {
  AesSivKeyFormat format;
  format.set_key_size(64);
  auto key_or = AesSivKeyManager().CreateKey(format);
  ASSERT_THAT(key_or, IsOk());
  auto daead_or =
      AesSivKeyManager().GetPrimitive<DeterministicAead>(key_or.value());
  ASSERT_THAT(daead_or, IsOk());

  auto direct_daead_or = subtle::AesSivBoringSsl::New(
      util::SecretDataFromStringView(key_or.value().key_value()));
  ASSERT_THAT(direct_daead_or, IsOk());

  auto encryption_or =
      daead_or.value()->EncryptDeterministically("123", "abcd");
  ASSERT_THAT(encryption_or, IsOk());
  auto direct_encryption_or =
      direct_daead_or.value()->EncryptDeterministically("123", "abcd");
  ASSERT_THAT(direct_encryption_or, IsOk());
  ASSERT_THAT(encryption_or.value(), Eq(direct_encryption_or.value()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
