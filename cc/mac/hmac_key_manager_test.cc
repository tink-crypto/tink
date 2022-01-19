// Copyright 2017 Google Inc.
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

#include "tink/mac/hmac_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/core/key_manager_impl.h"
#include "tink/mac.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/hmac.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacKey;
using ::google::crypto::tink::HmacKeyFormat;
using ::google::crypto::tink::KeyData;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(HmacKeyManagerTest, Basics) {
  EXPECT_EQ(HmacKeyManager().get_version(), 0);
  EXPECT_EQ(HmacKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.HmacKey");
  EXPECT_EQ(HmacKeyManager().key_material_type(),
            google::crypto::tink::KeyData::SYMMETRIC);
}

TEST(HmacKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(HmacKeyManager().ValidateKey(HmacKey()), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(HmacKeyFormat()), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidKeyFormat) {
  HmacKeyFormat key_format;
  key_format.mutable_params()->set_tag_size(16);
  key_format.mutable_params()->set_hash(HashType::SHA256);
  key_format.set_key_size(16);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(HmacKeyManagerTest, ValidateKeyFormatSmallTagSizes) {
  for (int i = 0; i < 10; ++i) {
    HmacKeyFormat key_format;
    key_format.mutable_params()->set_tag_size(i);
    key_format.mutable_params()->set_hash(HashType::SHA256);
    key_format.set_key_size(16);
    EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()))
        << " for length " << i;
  }
}

TEST(HmacKeyManagerTest, ValidateKeyFormatTagSizesSha1) {
  HmacKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA1);
  key_format.set_key_size(16);

  key_format.mutable_params()->set_tag_size(20);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.mutable_params()->set_tag_size(21);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyFormatTagSizesSha224) {
  HmacKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA224);
  key_format.set_key_size(16);

  key_format.mutable_params()->set_tag_size(28);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.mutable_params()->set_tag_size(29);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyFormatTagSizesSha256) {
  HmacKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA256);
  key_format.set_key_size(16);

  key_format.mutable_params()->set_tag_size(32);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.mutable_params()->set_tag_size(33);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyFormatTagSizesSha384) {
  HmacKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA384);
  key_format.set_key_size(16);

  key_format.mutable_params()->set_tag_size(48);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.mutable_params()->set_tag_size(49);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyFormatTagSizesSha512) {
  HmacKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA512);
  key_format.set_key_size(16);

  key_format.mutable_params()->set_tag_size(64);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.mutable_params()->set_tag_size(65);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyFormatKeySizes) {
  HmacKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA512);
  key_format.mutable_params()->set_tag_size(64);

  key_format.set_key_size(15);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));

  key_format.set_key_size(16);
  EXPECT_THAT(HmacKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(HmacKeyManagerTest, CreateKey) {
  HmacKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_tag_size(10);
  key_format.mutable_params()->set_hash(HashType::SHA512);
  auto hmac_key_or = HmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(hmac_key_or.status(), IsOk());
  EXPECT_EQ(hmac_key_or.ValueOrDie().version(), 0);
  EXPECT_EQ(hmac_key_or.ValueOrDie().params().hash(),
            key_format.params().hash());
  EXPECT_EQ(hmac_key_or.ValueOrDie().params().tag_size(),
            key_format.params().tag_size());
  EXPECT_THAT(hmac_key_or.ValueOrDie().key_value(),
              SizeIs(key_format.key_size()));

  EXPECT_THAT(HmacKeyManager().ValidateKey(hmac_key_or.ValueOrDie()), IsOk());
}

TEST(HmacKeyManagerTest, ValidKey) {
  HmacKey key;
  key.set_version(0);

  key.mutable_params()->set_hash(HashType::SHA256);
  key.mutable_params()->set_tag_size(10);
  key.set_key_value("0123456789abcdef");

  EXPECT_THAT(HmacKeyManager().ValidateKey(key), IsOk());
}

TEST(HmacKeyManagerTest, ValidateKeyTagSizesSha1) {
  HmacKey key;
  key.set_version(0);
  key.mutable_params()->set_hash(HashType::SHA1);
  key.set_key_value("0123456789abcdef");

  key.mutable_params()->set_tag_size(20);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), IsOk());
  key.mutable_params()->set_tag_size(21);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyTagSizesSha224) {
  HmacKey key;
  key.set_version(0);
  key.mutable_params()->set_hash(HashType::SHA224);
  key.set_key_value("0123456789abcdef");

  key.mutable_params()->set_tag_size(28);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), IsOk());
  key.mutable_params()->set_tag_size(29);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyTagSizesSha256) {
  HmacKey key;
  key.set_version(0);
  key.mutable_params()->set_hash(HashType::SHA256);
  key.set_key_value("0123456789abcdef");

  key.mutable_params()->set_tag_size(32);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), IsOk());
  key.mutable_params()->set_tag_size(33);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyTagSizesSha384) {
  HmacKey key;
  key.set_version(0);
  key.mutable_params()->set_hash(HashType::SHA384);
  key.set_key_value("0123456789abcdef");

  key.mutable_params()->set_tag_size(48);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), IsOk());
  key.mutable_params()->set_tag_size(49);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyTagSizesSha512) {
  HmacKey key;
  key.set_version(0);
  key.mutable_params()->set_hash(HashType::SHA512);
  key.set_key_value("0123456789abcdef");

  key.mutable_params()->set_tag_size(64);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), IsOk());
  key.mutable_params()->set_tag_size(65);
  EXPECT_THAT(HmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(HmacKeyManagerTest, ValidateKeyShortKey) {
  HmacKey key;
  key.set_version(0);

  key.mutable_params()->set_hash(HashType::SHA256);
  key.mutable_params()->set_tag_size(10);
  key.set_key_value("0123456789abcde");

  EXPECT_THAT(HmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(HmacKeyManagerTest, DeriveKey) {
  HmacKeyFormat format;
  format.set_key_size(23);
  format.set_version(0);
  format.mutable_params()->set_hash(HashType::SHA256);
  format.mutable_params()->set_tag_size(10);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};

  StatusOr<HmacKey> key_or = HmacKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_EQ(key_or.ValueOrDie().key_value(), "0123456789abcdefghijklm");
  EXPECT_EQ(key_or.ValueOrDie().params().hash(), format.params().hash());
  EXPECT_EQ(key_or.ValueOrDie().params().tag_size(),
            format.params().tag_size());
}

TEST(HmacKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  HmacKeyFormat format;
  format.set_key_size(17);
  format.set_version(0);
  format.mutable_params()->set_hash(HashType::SHA256);
  format.mutable_params()->set_tag_size(10);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef")};

  ASSERT_THAT(HmacKeyManager().DeriveKey(format, &input_stream).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HmacKeyManagerTest, DeriveKeyWrongVersion) {
  HmacKeyFormat format;
  format.set_key_size(16);
  format.set_version(1);
  format.mutable_params()->set_hash(HashType::SHA256);
  format.mutable_params()->set_tag_size(10);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef")};

  ASSERT_THAT(
      HmacKeyManager().DeriveKey(format, &input_stream).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("version")));
}

TEST(HmacKeyManagerTest, GetPrimitive) {
  HmacKeyFormat key_format;
  key_format.mutable_params()->set_tag_size(16);
  key_format.mutable_params()->set_hash(HashType::SHA256);
  key_format.set_key_size(16);
  HmacKey key = HmacKeyManager().CreateKey(key_format).ValueOrDie();
  auto manager_mac_or = HmacKeyManager().GetPrimitive<Mac>(key);
  ASSERT_THAT(manager_mac_or.status(), IsOk());
  auto mac_value_or = manager_mac_or.ValueOrDie()->ComputeMac("some plaintext");
  ASSERT_THAT(mac_value_or.status(), IsOk());

  auto direct_mac_or = subtle::HmacBoringSsl::New(
      util::Enums::ProtoToSubtle(key.params().hash()), key.params().tag_size(),
      util::SecretDataFromStringView(key.key_value()));
  ASSERT_THAT(direct_mac_or.status(), IsOk());
  EXPECT_THAT(direct_mac_or.ValueOrDie()->VerifyMac(mac_value_or.ValueOrDie(),
                                                    "some plaintext"),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
