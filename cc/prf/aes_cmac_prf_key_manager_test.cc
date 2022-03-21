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
#include "tink/prf/aes_cmac_prf_key_manager.h"

#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/subtle/aes_cmac_boringssl.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac_prf.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::AesCmacPrfKey;
using ::google::crypto::tink::AesCmacPrfKeyFormat;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::StrEq;

std::unique_ptr<InputStream> GetInputStreamForString(const std::string& input) {
  return absl::make_unique<util::IstreamInputStream>(
      absl::make_unique<std::stringstream>(input));
}

AesCmacPrfKeyFormat ValidKeyFormat() {
  AesCmacPrfKeyFormat format;
  format.set_key_size(32);
  return format;
}

TEST(AesCmacPrfKeyManagerTest, Basics) {
  EXPECT_THAT(AesCmacPrfKeyManager().get_version(), Eq(0));
  EXPECT_THAT(AesCmacPrfKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacPrfKey"));
  EXPECT_THAT(AesCmacPrfKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesCmacPrfKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKey(AesCmacPrfKey()), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(AesCmacPrfKeyFormat()),
              Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, ValidateSimpleKeyFormat) {
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(ValidKeyFormat()),
              IsOk());
}

TEST(AesCmacPrfKeyManagerTest, ValidateKeyFormatKeySizes) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();

  format.set_key_size(0);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(1);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(15);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(16);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(17);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(31);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));

  format.set_key_size(32);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), IsOk());

  format.set_key_size(33);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKeyFormat(format), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, CreateKey) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  ASSERT_THAT(AesCmacPrfKeyManager().CreateKey(format).status(), IsOk());
  AesCmacPrfKey key = AesCmacPrfKeyManager().CreateKey(format).value();
  EXPECT_THAT(key.version(), Eq(0));
  EXPECT_THAT(key.key_value(), SizeIs(format.key_size()));
}

TEST(AesCmacPrfKeyManagerTest, ValidateKey) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  AesCmacPrfKey key = AesCmacPrfKeyManager().CreateKey(format).value();
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKey(key), IsOk());
}

TEST(AesCmacPrfKeyManagerTest, ValidateKeyInvalidVersion) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  AesCmacPrfKey key = AesCmacPrfKeyManager().CreateKey(format).value();
  key.set_version(1);
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, ValidateKeyShortKey) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  AesCmacPrfKey key = AesCmacPrfKeyManager().CreateKey(format).value();
  key.set_key_value("0123456789abcdef");
  EXPECT_THAT(AesCmacPrfKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, GetPrimitive) {
  AesCmacPrfKeyFormat format = ValidKeyFormat();
  AesCmacPrfKey key = AesCmacPrfKeyManager().CreateKey(format).value();
  auto manager_prf_or = AesCmacPrfKeyManager().GetPrimitive<Prf>(key);
  ASSERT_THAT(manager_prf_or.status(), IsOk());
  auto prf_value_or = manager_prf_or.value()->Compute("some plaintext", 16);
  ASSERT_THAT(prf_value_or.status(), IsOk());

  auto direct_prf_or = subtle::AesCmacBoringSsl::New(
      util::SecretDataFromStringView(key.key_value()), 16);
  ASSERT_THAT(direct_prf_or.status(), IsOk());
  auto direct_prf_value_or =
      direct_prf_or.value()->ComputeMac("some plaintext");
  ASSERT_THAT(direct_prf_value_or.status(), IsOk());
  EXPECT_THAT(direct_prf_value_or.value(), StrEq(prf_value_or.value()));
}

TEST(AesCmacPrfKeyManagerTest, DeriveKeyValid) {
  std::string bytes = "0123456789abcdef0123456789abcdef";
  auto inputstream = GetInputStreamForString(bytes);
  auto key_or =
      AesCmacPrfKeyManager().DeriveKey(ValidKeyFormat(), inputstream.get());
  ASSERT_THAT(key_or.status(), IsOk());
  AesCmacPrfKey key = key_or.value();
  EXPECT_THAT(key.version(), Eq(AesCmacPrfKeyManager().get_version()));
  EXPECT_THAT(key.key_value(), Eq(bytes));
}

TEST(AesCmacPrfKeyManagerTest, DeriveKeyNotEnoughRandomness) {
  std::string bytes = "0123456789abcdef";
  auto inputstream = GetInputStreamForString(bytes);
  auto key_or =
      AesCmacPrfKeyManager().DeriveKey(ValidKeyFormat(), inputstream.get());
  EXPECT_THAT(key_or.status(), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, DeriveKeyInvalidFormat) {
  std::string bytes = "0123456789abcdef";
  auto inputstream = GetInputStreamForString(bytes);
  auto format = ValidKeyFormat();
  format.set_key_size(12);
  auto key_or = AesCmacPrfKeyManager().DeriveKey(format, inputstream.get());
  EXPECT_THAT(key_or.status(), Not(IsOk()));
}

TEST(AesCmacPrfKeyManagerTest, DeriveKeyInvalidVersion) {
  auto format = ValidKeyFormat();
  format.set_version(1);
  std::string bytes = "0123456789abcdef0123456789abcdef";
  auto inputstream = GetInputStreamForString(bytes);
  auto key_or =
      AesCmacPrfKeyManager().DeriveKey(format, inputstream.get());
  EXPECT_THAT(key_or.status(), Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
