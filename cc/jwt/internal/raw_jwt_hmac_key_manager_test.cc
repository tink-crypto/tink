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

#include "tink/jwt/internal/raw_jwt_hmac_key_manager.h"

#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/mac_config.h"
#include "tink/registry.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/jwt_hmac.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::JwtHmacAlgorithm;
using ::google::crypto::tink::JwtHmacKey;
using ::google::crypto::tink::JwtHmacKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(RawJwtHmacKeyManagerTest, Basics) {
  EXPECT_THAT(RawJwtHmacKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RawJwtHmacKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.JwtHmacKey"));
  EXPECT_THAT(RawJwtHmacKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(RawJwtHmacKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKey(JwtHmacKey()), Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKeyFormat(JwtHmacKeyFormat()),
              Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, ValidKeyFormat) {
  JwtHmacKeyFormat key_format;
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  key_format.set_key_size(32);
  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(RawJwtHmacKeyManagerTest, SmallKeySizeIsInvalidKeyFormat) {
  JwtHmacKeyFormat key_format;
  key_format.set_algorithm(JwtHmacAlgorithm::HS512);
  key_format.set_key_size(31);
  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, Sha1IsInvalidKeyFormat) {
  JwtHmacKeyFormat key_format;
  key_format.set_algorithm(JwtHmacAlgorithm::HS_UNKNOWN);
  key_format.set_key_size(32);
  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, CreateKeyWithSha256) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  auto hmac_key_or = RawJwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(hmac_key_or.status(), IsOk());
  EXPECT_THAT(hmac_key_or.value().version(), Eq(0));
  EXPECT_THAT(hmac_key_or.value().algorithm(), Eq(key_format.algorithm()));
  EXPECT_THAT(hmac_key_or.value().key_value(), SizeIs(key_format.key_size()));

  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKey(hmac_key_or.value()), IsOk());
}

TEST(RawJwtHmacKeyManagerTest, CreateKeyWithSha384) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS384);
  auto hmac_key_or = RawJwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(hmac_key_or.status(), IsOk());
  EXPECT_THAT(hmac_key_or.value().version(), Eq(0));
  EXPECT_THAT(hmac_key_or.value().algorithm(), Eq(key_format.algorithm()));
  EXPECT_THAT(hmac_key_or.value().key_value(), SizeIs(key_format.key_size()));

  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKey(hmac_key_or.value()), IsOk());
}

TEST(RawJwtHmacKeyManagerTest, CreateKeyWithSha512) {
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_algorithm(JwtHmacAlgorithm::HS512);
  auto key_or = RawJwtHmacKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.value().version(), Eq(0));
  EXPECT_THAT(key_or.value().algorithm(), Eq(key_format.algorithm()));
  EXPECT_THAT(key_or.value().key_value(), SizeIs(key_format.key_size()));

  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKey(key_or.value()), IsOk());
}

TEST(RawJwtHmacKeyManagerTest, ShortKeyIsInvalid) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_algorithm(JwtHmacAlgorithm::HS256);
  key.set_key_value("0123456789abcdef0123456789abcde");  // 31 bytes
  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, Sha1KeyIsInvalid) {
  JwtHmacKey key;
  key.set_version(0);
  key.set_algorithm(JwtHmacAlgorithm::HS_UNKNOWN);
  key.set_key_value("0123456789abcdef0123456789abcdef");
  EXPECT_THAT(RawJwtHmacKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(RawJwtHmacKeyManagerTest, DeriveKeyIsNotImplemented) {
  JwtHmacKeyFormat format;
  format.set_key_size(32);
  format.set_version(0);
  format.set_algorithm(JwtHmacAlgorithm::HS256);
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdef0123456789abcdef")};

  StatusOr<JwtHmacKey> key_or =
      RawJwtHmacKeyManager().DeriveKey(format, &input_stream);
  EXPECT_THAT(key_or.status(), StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(RawJwtHmacKeyManagerTest, GetPrimitiveFromNewKeysetHandle) {
  Registry::Reset();
  ASSERT_THAT(MacConfig::Register(), IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<RawJwtHmacKeyManager>(), true),
              IsOk());

  JwtHmacKeyFormat key_format;
  key_format.set_algorithm(JwtHmacAlgorithm::HS256);
  key_format.set_key_size(32);
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtHmacKey");
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  key_format.SerializeToString(key_template.mutable_value());

  auto handle_result = KeysetHandle::GenerateNew(key_template);
  ASSERT_TRUE(handle_result.ok()) << handle_result.status();
  std::unique_ptr<KeysetHandle> handle = std::move(handle_result.value());

  auto mac_result = handle->GetPrimitive<Mac>();
  ASSERT_TRUE(mac_result.ok()) << mac_result.status();
  std::unique_ptr<Mac> mac = std::move(mac_result.value());
  auto tag_or = mac->ComputeMac("some plaintext");
  ASSERT_THAT(tag_or.status(), IsOk());
  EXPECT_THAT(mac->VerifyMac(tag_or.value(), "some plaintext"), IsOk());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
