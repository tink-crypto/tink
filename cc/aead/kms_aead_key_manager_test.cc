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

#include "tink/aead/kms_aead_key_manager.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "tink/aead.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/subtle/aead_test_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/kms_aead.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::DummyKmsClient;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KmsAeadKey;
using ::google::crypto::tink::KmsAeadKeyFormat;
using ::testing::Eq;
using ::testing::Not;

namespace {

TEST(KmsAeadKeyManagerTest, Basics) {
  EXPECT_THAT(KmsAeadKeyManager().get_version(), Eq(0));
  EXPECT_THAT(KmsAeadKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.KmsAeadKey"));
  EXPECT_THAT(KmsAeadKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::REMOTE));
}

TEST(KmsAeadKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(KmsAeadKeyManager().ValidateKey(KmsAeadKey()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsAeadKeyManagerTest, ValidateValidKey) {
  KmsAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_key_uri("Some uri");
  EXPECT_THAT(KmsAeadKeyManager().ValidateKey(key), IsOk());
}

TEST(KmsAeadKeyManagerTest, ValidateWrongVersion) {
  KmsAeadKey key;
  key.set_version(1);
  key.mutable_params()->set_key_uri("Some uri");
  EXPECT_THAT(KmsAeadKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(KmsAeadKeyManagerTest, ValidateNoUri) {
  KmsAeadKey key;
  key.set_version(0);
  EXPECT_THAT(KmsAeadKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(KmsAeadKeyManagerTest, ValidateKeyFormatEmptyKey) {
  EXPECT_THAT(KmsAeadKeyManager().ValidateKeyFormat(KmsAeadKeyFormat()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsAeadKeyManagerTest, ValidateKeyFormatValidKey) {
  KmsAeadKeyFormat key_format;
  key_format.set_key_uri("Some uri");
  EXPECT_THAT(KmsAeadKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(KmsAeadKeyManagerTest, ValidateKeyFormatNoUri) {
  KmsAeadKeyFormat key_format;
  EXPECT_THAT(KmsAeadKeyManager().ValidateKeyFormat(key_format), Not(IsOk()));
}

TEST(KmsAeadKeyManagerTest, CreateKey) {
  KmsAeadKeyFormat key_format;
  key_format.set_key_uri("Some uri");
  auto key_or = KmsAeadKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().params().key_uri(), Eq(key_format.key_uri()));
}

class KmsAeadKeyManagerCreateTest : public ::testing::Test {
 public:
  // The KmsClients class has a global variable which keeps the registered
  // clients. To reflect that in the test, we set them up in the SetUpTestSuite
  // function.
  static void SetUpTestSuite() {
    if (!KmsClients::Add(
             absl::make_unique<DummyKmsClient>("prefix1", "prefix1:some_key1"))
             .ok())
      abort();
    if (!KmsClients::Add(absl::make_unique<DummyKmsClient>("prefix2", "")).ok())
      abort();
  }
};

TEST_F(KmsAeadKeyManagerCreateTest, CreateAead) {
  KmsAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_key_uri("prefix1:some_key1");

  auto kms_aead = KmsAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead.status(), IsOk());

  DummyAead direct_aead("prefix1:some_key1");

  EXPECT_THAT(EncryptThenDecrypt(*kms_aead.ValueOrDie(), direct_aead,
                                 "plaintext", "aad"),
              IsOk());
}

TEST_F(KmsAeadKeyManagerCreateTest, CreateAeadWrongKeyName) {
  KmsAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_key_uri("prefix1:some_other_key");

  auto kms_aead = KmsAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead.status(), Not(IsOk()));
}

TEST_F(KmsAeadKeyManagerCreateTest, CreateAeadWrongPrefix) {
  KmsAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_key_uri("non-existing-prefix:some_key1");

  auto kms_aead = KmsAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead.status(), Not(IsOk()));
}

TEST_F(KmsAeadKeyManagerCreateTest, CreateAeadUnboundKey) {
  KmsAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_key_uri("prefix2:some_key2");

  auto kms_aead = KmsAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead.status(), IsOk());

  DummyAead direct_aead("prefix2:some_key2");

  EXPECT_THAT(EncryptThenDecrypt(*kms_aead.ValueOrDie(), direct_aead,
                                 "plaintext", "aad"),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
