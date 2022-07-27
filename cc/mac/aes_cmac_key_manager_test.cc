// Copyright 2019 Google LLC
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
#include "tink/mac/aes_cmac_key_manager.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/chunked_mac.h"
#include "tink/mac.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::AesCmacKey;
using ::google::crypto::tink::AesCmacKeyFormat;
using ::google::crypto::tink::AesCmacParams;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

TEST(AesCmacKeyManagerTest, Basics) {
  EXPECT_THAT(AesCmacKeyManager().get_version(), Eq(0));
  EXPECT_THAT(AesCmacKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));
  EXPECT_THAT(AesCmacKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesCmacKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(AesCmacKeyManager().ValidateKey(AesCmacKey()), Not(IsOk()));
}

AesCmacParams ValidParams() {
  AesCmacParams params;
  params.set_tag_size(16);
  return params;
}

AesCmacKeyFormat ValidKeyFormat() {
  AesCmacKeyFormat format;
  *format.mutable_params() = ValidParams();
  format.set_key_size(32);
  return format;
}

TEST(AesCmacKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(AesCmacKeyFormat()),
              Not(IsOk()));
}

TEST(AesCmacKeyManagerTest, ValidateSimpleKeyFormat) {
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(ValidKeyFormat()), IsOk());
}

TEST(AesCmacKeyManagerTest, ValidateKeyFormatKeySizes) {
  AesCmacKeyFormat format = ValidKeyFormat();

  format.set_key_size(0);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(1);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(15);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(16);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(17);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(31);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(32);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), IsOk());

  format.set_key_size(33);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));
}

TEST(AesCmacKeyManagerTest, ValidateKeyFormatTagSizes) {
  AesCmacKeyFormat format = ValidKeyFormat();

  format.mutable_params()->set_tag_size(0);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.mutable_params()->set_tag_size(9);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.mutable_params()->set_tag_size(10);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), IsOk());

  format.mutable_params()->set_tag_size(11);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), IsOk());

  format.mutable_params()->set_tag_size(12);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), IsOk());

  format.mutable_params()->set_tag_size(15);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), IsOk());

  format.mutable_params()->set_tag_size(16);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), IsOk());

  format.mutable_params()->set_tag_size(17);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.mutable_params()->set_tag_size(32);
  EXPECT_THAT(AesCmacKeyManager().ValidateKeyFormat(format), Not(IsOk()));
}

TEST(AesCmacKeyManagerTest, CreateKey) {
  AesCmacKeyFormat format = ValidKeyFormat();
  ASSERT_THAT(AesCmacKeyManager().CreateKey(format), IsOk());
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();
  EXPECT_THAT(key.version(), Eq(0));
  EXPECT_THAT(key.key_value(), SizeIs(format.key_size()));
  EXPECT_THAT(key.params().tag_size(), Eq(format.params().tag_size()));
}

TEST(AesCmacKeyManagerTest, ValidateKey) {
  AesCmacKeyFormat format = ValidKeyFormat();
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();
  EXPECT_THAT(AesCmacKeyManager().ValidateKey(key), IsOk());
}

TEST(AesCmacKeyManagerTest, ValidateKeyInvalidVersion) {
  AesCmacKeyFormat format = ValidKeyFormat();
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();
  key.set_version(1);
  EXPECT_THAT(AesCmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(AesCmacKeyManagerTest, ValidateKeyShortKey) {
  AesCmacKeyFormat format = ValidKeyFormat();
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();
  key.set_key_value("0123456789abcdef");
  EXPECT_THAT(AesCmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(AesCmacKeyManagerTest, ValidateKeyLongTagSize) {
  AesCmacKeyFormat format = ValidKeyFormat();
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();
  key.mutable_params()->set_tag_size(17);
  EXPECT_THAT(AesCmacKeyManager().ValidateKey(key), Not(IsOk()));
}


TEST(AesCmacKeyManagerTest, ValidateKeyTooShortTagSize) {
  AesCmacKeyFormat format = ValidKeyFormat();
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();
  key.mutable_params()->set_tag_size(9);
  EXPECT_THAT(AesCmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(AesCmacKeyManagerTest, GetMacPrimitive) {
  AesCmacKeyFormat format = ValidKeyFormat();
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();
  auto manager_mac_or = AesCmacKeyManager().GetPrimitive<Mac>(key);
  ASSERT_THAT(manager_mac_or, IsOk());
  auto mac_value_or = manager_mac_or.value()->ComputeMac("some plaintext");
  ASSERT_THAT(mac_value_or, IsOk());

  auto direct_mac_or = subtle::AesCmacBoringSsl::New(
      util::SecretDataFromStringView(key.key_value()), key.params().tag_size());
  ASSERT_THAT(direct_mac_or, IsOk());
  EXPECT_THAT(
      direct_mac_or.value()->VerifyMac(mac_value_or.value(), "some plaintext"),
      IsOk());
}

TEST(AesCmacKeyManagerTest, GetChunkedMacPrimitive) {
  AesCmacKeyFormat format = ValidKeyFormat();
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();

  util::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      AesCmacKeyManager().GetPrimitive<ChunkedMac>(key);
  ASSERT_THAT(chunked_mac, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update("abc"), IsOk());
  ASSERT_THAT((*computation)->Update("xyz"), IsOk());
  util::StatusOr<std::string> tag = (*computation)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update("abc"), IsOk());
  ASSERT_THAT((*verification)->Update("xyz"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST(AesCmacKeyManagerTest, MixPrimitives) {
  AesCmacKeyFormat format = ValidKeyFormat();
  AesCmacKey key = AesCmacKeyManager().CreateKey(format).value();

  util::StatusOr<std::unique_ptr<Mac>> mac =
      AesCmacKeyManager().GetPrimitive<Mac>(key);
  ASSERT_THAT(mac, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      AesCmacKeyManager().GetPrimitive<ChunkedMac>(key);
  ASSERT_THAT(chunked_mac, IsOk());

  // Compute tag with Mac.
  util::StatusOr<std::string> tag = (*mac)->ComputeMac("abcxyz");
  ASSERT_THAT(tag, IsOk());

  // Compute chunked tag with ChunkedMac.
  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update("abc"), IsOk());
  ASSERT_THAT((*computation)->Update("xyz"), IsOk());
  util::StatusOr<std::string> chunked_tag = (*computation)->ComputeMac();
  ASSERT_THAT(chunked_tag, IsOk());
  ASSERT_THAT(*chunked_tag, Eq(*tag));  // Both primitives generated same tag.

  // Verify chunked tag with Mac.
  ASSERT_THAT((*mac)->VerifyMac(*chunked_tag, "abcxyz"), IsOk());

  // Verify tag with ChunkedMac.
  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update("abc"), IsOk());
  ASSERT_THAT((*verification)->Update("xyz"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
