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

#include "tink/aead/aes_gcm_siv_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/subtle/aead_test_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm_siv.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesGcmSivKey;
using ::google::crypto::tink::AesGcmSivKeyFormat;
using ::testing::Eq;

TEST(AesGcmSivKeyManagerTest, Basics) {
  EXPECT_THAT(AesGcmSivKeyManager().get_version(), Eq(0));
  EXPECT_THAT(AesGcmSivKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmSivKey"));
  EXPECT_THAT(AesGcmSivKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesGcmSivKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKey(AesGcmSivKey()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmSivKeyManagerTest, ValidateValid16ByteKey) {
  AesGcmSivKey key;
  key.set_version(0);
  key.set_key_value("0123456789abcdef");
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKey(key), IsOk());
}

TEST(AesGcmSivKeyManagerTest, ValidateValid32ByteKey) {
  AesGcmSivKey key;
  key.set_version(0);
  key.set_key_value("01234567890123456789012345678901");
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKey(key), IsOk());
}

TEST(AesGcmSivKeyManagerTest, InvalidKeySizes17Bytes) {
  AesGcmSivKey key;
  key.set_version(0);
  key.set_key_value("0123456789abcdefg");
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmSivKeyManagerTest, InvalidKeySizes24Bytes) {
  AesGcmSivKey key;
  key.set_version(0);
  key.set_key_value("01234567890123");
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmSivKeyManagerTest, InvalidKeySizes31Bytes) {
  AesGcmSivKey key;
  key.set_version(0);
  key.set_key_value("0123456789012345678901234567890");
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmSivKeyManagerTest, InvalidKeySizes33Bytes) {
  AesGcmSivKey key;
  key.set_version(0);
  key.set_key_value("012345678901234567890123456789012");
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmSivKeyManagerTest, ValidateKeyFormat) {
  AesGcmSivKeyFormat format;

  format.set_key_size(0);
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(1);
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(15);
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(16);
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKeyFormat(format), IsOk());

  format.set_key_size(17);
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(31);
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));

  format.set_key_size(32);
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKeyFormat(format), IsOk());

  format.set_key_size(33);
  EXPECT_THAT(AesGcmSivKeyManager().ValidateKeyFormat(format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmSivKeyManagerTest, Create16ByteKey) {
  AesGcmSivKeyFormat format;
  format.set_key_size(16);

  StatusOr<AesGcmSivKey> key_or = AesGcmSivKeyManager().CreateKey(format);

  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_value().size(), Eq(format.key_size()));
}

TEST(AesGcmSivKeyManagerTest, Create32ByteKey) {
  AesGcmSivKeyFormat format;
  format.set_key_size(32);

  StatusOr<AesGcmSivKey> key_or = AesGcmSivKeyManager().CreateKey(format);

  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_value().size(), Eq(format.key_size()));
}

TEST(AesGcmSivKeyManagerTest, CreateAead) {
  AesGcmSivKeyFormat format;
  format.set_key_size(32);
  StatusOr<AesGcmSivKey> key_or = AesGcmSivKeyManager().CreateKey(format);
  ASSERT_THAT(key_or.status(), IsOk());

  StatusOr<std::unique_ptr<Aead>> aead_or =
      AesGcmSivKeyManager().GetPrimitive<Aead>(key_or.ValueOrDie());

  ASSERT_THAT(aead_or.status(), IsOk());

  StatusOr<std::unique_ptr<Aead>> boring_ssl_aead_or =
      subtle::AesGcmSivBoringSsl::New(
          util::SecretDataFromStringView(key_or.ValueOrDie().key_value()));
  ASSERT_THAT(boring_ssl_aead_or.status(), IsOk());

  ASSERT_THAT(EncryptThenDecrypt(*aead_or.ValueOrDie().get(),
                                 *boring_ssl_aead_or.ValueOrDie().get(),
                                 "message", "aad"),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
