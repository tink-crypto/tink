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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/deterministic_aead.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_siv.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::AesSivKey;
using ::google::crypto::tink::AesSivKeyFormat;
using ::testing::Eq;
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
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_value(), SizeIs(format.key_size()));
  EXPECT_THAT(key_or.ValueOrDie().version(), Eq(0));
}

TEST(AesSivKeyManagerTest, CreateKeyIsValid) {
  AesSivKeyFormat format;
  format.set_key_size(64);
  auto key_or = AesSivKeyManager().CreateKey(format);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(AesSivKeyManager().ValidateKey(key_or.ValueOrDie()), IsOk());
}

TEST(AesSivKeyManagerTest, MultipleCreateCallsCreateDifferentKeys) {
  AesSivKeyFormat format;
  AesSivKeyManager manager;
  format.set_key_size(64);
  auto key1_or = manager.CreateKey(format);
  ASSERT_THAT(key1_or.status(), IsOk());
  auto key2_or = manager.CreateKey(format);
  ASSERT_THAT(key2_or.status(), IsOk());
  EXPECT_THAT(key1_or.ValueOrDie().key_value(),
              Ne(key2_or.ValueOrDie().key_value()));
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
  ASSERT_THAT(key_or.status(), IsOk());
  auto daead_or =
      AesSivKeyManager().GetPrimitive<DeterministicAead>(key_or.ValueOrDie());
  ASSERT_THAT(daead_or.status(), IsOk());

  auto direct_daead_or = subtle::AesSivBoringSsl::New(
      util::SecretDataFromStringView(key_or.ValueOrDie().key_value()));
  ASSERT_THAT(direct_daead_or.status(), IsOk());

  auto encryption_or =
      daead_or.ValueOrDie()->EncryptDeterministically("123", "abcd");
  ASSERT_THAT(encryption_or.status(), IsOk());
  auto direct_encryption_or =
      direct_daead_or.ValueOrDie()->EncryptDeterministically("123", "abcd");
  ASSERT_THAT(direct_encryption_or.status(), IsOk());
  ASSERT_THAT(encryption_or.ValueOrDie(),
              Eq(direct_encryption_or.ValueOrDie()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
