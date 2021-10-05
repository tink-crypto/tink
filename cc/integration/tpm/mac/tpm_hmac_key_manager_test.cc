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
#include "tink/integration/tpm/mac/tpm_hmac_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tpm_hmac.pb.h"

namespace crypto {
namespace tink {
namespace integration {
namespace tpm {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::TpmHmacKey;
using ::google::crypto::tink::TpmHmacKeyFormat;
using ::testing::Not;

TEST(TpmHmacKeyManagerTest, Basics) {
  EXPECT_EQ(TpmHmacKeyManager().get_version(), 0);
  EXPECT_EQ(TpmHmacKeyManager().get_key_type(),
            "type.googleapis.com/google.crypto.tink.TpmHmacKey");
  EXPECT_EQ(TpmHmacKeyManager().key_material_type(),
            google::crypto::tink::KeyData::REMOTE);
}

TEST(TpmHmacKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(TpmHmacKeyManager().ValidateKey(TpmHmacKey()), Not(IsOk()));
}

TEST(TpmHmacKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(TpmHmacKeyFormat()),
              Not(IsOk()));
}

TEST(TpmHmacKeyManagerTest, ValidateKey) {
  TpmHmacKey key;
  key.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  key.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA256);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKey(key), IsOk());
}

TEST(TpmHmacKeyManagerTest, ValidKeyFormat) {
  TpmHmacKeyFormat key_format;
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  key_format.mutable_params()->mutable_hmac_params()->set_hash(
      HashType::SHA256);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(TpmHmacKeyManagerTest, ValidateKeyFormatSmallTagSizes) {
  TpmHmacKeyFormat key_format;
  key_format.mutable_params()->mutable_hmac_params()->set_hash(
      HashType::SHA256);
  for (int i = 0; i < 20; ++i) {
    key_format.mutable_params()->mutable_hmac_params()->set_tag_size(i);
    EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()))
        << " for length " << i;
  }
}

TEST(TpmHmacKeyManagerTest, ValidateKeyFormatTagSizesSha1) {
  TpmHmacKeyFormat key_format;
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(20);
  key_format.mutable_params()->mutable_hmac_params()->set_hash(HashType::SHA1);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(21);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(TpmHmacKeyManagerTest, ValidateKeyFormatTagSizesSha256) {
  TpmHmacKeyFormat key_format;
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(32);
  key_format.mutable_params()->mutable_hmac_params()->set_hash(
      HashType::SHA256);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(33);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(TpmHmacKeyManagerTest, ValidateKeyFormatTagSizesSha384) {
  TpmHmacKeyFormat key_format;
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(48);
  key_format.mutable_params()->mutable_hmac_params()->set_hash(
      HashType::SHA384);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), IsOk());
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(49);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(TpmHmacKeyManagerTest, ValidateHashNotSupported) {
  TpmHmacKeyFormat key_format;
  key_format.mutable_params()->mutable_hmac_params()->set_tag_size(28);
  key_format.mutable_params()->mutable_hmac_params()->set_hash(
      HashType::SHA224);
  EXPECT_THAT(TpmHmacKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

}  // namespace
}  // namespace tpm
}  // namespace integration
}  // namespace tink
}  // namespace crypto
