// Copyright 2020 Google LLC
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

#include "tink/prf/hmac_prf_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/prf/prf_set.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/hmac_prf.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacPrfKey;
using ::google::crypto::tink::HmacPrfKeyFormat;
using ::google::crypto::tink::KeyData;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::StartsWith;

namespace {

TEST(HmacPrfKeyManagerTest, Basics) {
  EXPECT_EQ(HmacPrfKeyManager().get_version(), 0);
  EXPECT_EQ(HmacPrfKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.HmacPrfKey");
  EXPECT_EQ(HmacPrfKeyManager().key_material_type(),
            google::crypto::tink::KeyData::SYMMETRIC);
}

TEST(HmacPrfKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(HmacPrfKeyManager().ValidateKey(HmacPrfKey()), Not(IsOk()));
}

TEST(HmacPrfKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(HmacPrfKeyManager().ValidateKeyFormat(HmacPrfKeyFormat()),
              Not(IsOk()));
}

TEST(HmacPrfKeyManagerTest, ValidKeyFormat) {
  HmacPrfKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA256);
  key_format.set_key_size(16);
  EXPECT_THAT(HmacPrfKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(HmacPrfKeyManagerTest, InvalidKeyFormatShortKey) {
  HmacPrfKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA512);

  key_format.set_key_size(15);
  EXPECT_THAT(HmacPrfKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(HmacPrfKeyManagerTest, CreateKey) {
  HmacPrfKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_hash(HashType::SHA512);
  auto hmac_key_or = HmacPrfKeyManager().CreateKey(key_format);
  ASSERT_THAT(hmac_key_or.status(), IsOk());
  EXPECT_EQ(hmac_key_or.ValueOrDie().version(), 0);
  EXPECT_EQ(hmac_key_or.ValueOrDie().params().hash(),
            key_format.params().hash());
  EXPECT_THAT(hmac_key_or.ValueOrDie().key_value(),
              SizeIs(key_format.key_size()));

  EXPECT_THAT(HmacPrfKeyManager().ValidateKey(hmac_key_or.ValueOrDie()),
              IsOk());
}

TEST(HmacPrfKeyManagerTest, ValidKey) {
  HmacPrfKey key;
  key.set_version(0);

  key.mutable_params()->set_hash(HashType::SHA256);
  key.set_key_value("0123456789abcdef");

  EXPECT_THAT(HmacPrfKeyManager().ValidateKey(key), IsOk());
}

TEST(HmacPrfKeyManagerTest, ValidateKeyShortKey) {
  HmacPrfKey key;
  key.set_version(0);

  key.mutable_params()->set_hash(HashType::SHA256);
  key.set_key_value("0123456789abcde");

  EXPECT_THAT(HmacPrfKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(HmacPrfKeyManagerTest, DeriveKey) {
  HmacPrfKeyFormat format;
  format.set_key_size(23);
  format.set_version(0);
  format.mutable_params()->set_hash(HashType::SHA256);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};

  StatusOr<HmacPrfKey> key_or =
      HmacPrfKeyManager().DeriveKey(format, &input_stream);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_EQ(key_or.ValueOrDie().key_value(), "0123456789abcdefghijklm");
  EXPECT_EQ(key_or.ValueOrDie().params().hash(), format.params().hash());
}

TEST(HmacPrfKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  HmacPrfKeyFormat format;
  format.set_key_size(17);
  format.set_version(0);
  format.mutable_params()->set_hash(HashType::SHA256);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef")};

  ASSERT_THAT(HmacPrfKeyManager().DeriveKey(format, &input_stream).status(),
              Not(IsOk()));
}

TEST(HmacPrfKeyManagerTest, DeriveKeyWrongVersion) {
  HmacPrfKeyFormat format;
  format.set_key_size(16);
  format.set_version(1);
  format.mutable_params()->set_hash(HashType::SHA256);

  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef")};

  ASSERT_THAT(HmacPrfKeyManager().DeriveKey(format, &input_stream).status(),
              StatusIs(util::error::INVALID_ARGUMENT, HasSubstr("version")));
}

TEST(HmacPrfKeyManagerTest, GetPrimitive) {
  HmacPrfKeyFormat key_format;
  key_format.mutable_params()->set_hash(HashType::SHA256);
  key_format.set_key_size(16);
  HmacPrfKey key = HmacPrfKeyManager().CreateKey(key_format).ValueOrDie();
  auto manager_mac_or = HmacPrfKeyManager().GetPrimitive<Prf>(key);
  ASSERT_THAT(manager_mac_or.status(), IsOk());
  auto prf_value_or =
      manager_mac_or.ValueOrDie()->Compute("some plaintext", 16);
  ASSERT_THAT(prf_value_or.status(), IsOk());

  auto direct_prf_or = subtle::HmacBoringSsl::New(
      util::Enums::ProtoToSubtle(key.params().hash()), 16,
      util::SecretDataFromStringView(key.key_value()));
  ASSERT_THAT(direct_prf_or.status(), IsOk());
  auto direct_prf_value_or =
      direct_prf_or.ValueOrDie()->ComputeMac("some plaintext");
  ASSERT_THAT(direct_prf_value_or.status(), IsOk());
  EXPECT_THAT(direct_prf_value_or.ValueOrDie(),
              StartsWith(prf_value_or.ValueOrDie()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
