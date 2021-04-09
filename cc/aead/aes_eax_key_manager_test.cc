// Copyright 2018 Google LLC
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

#include "tink/aead/aes_eax_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/subtle/aead_test_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_eax.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesEaxKey;
using ::google::crypto::tink::AesEaxKeyFormat;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

TEST(AesEaxKeyManagerTest, Basics) {
  EXPECT_THAT(AesEaxKeyManager().get_version(), Eq(0));
  EXPECT_THAT(AesEaxKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.AesEaxKey"));
  EXPECT_THAT(AesEaxKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
}

TEST(AesEaxKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(AesEaxKeyManager().ValidateKey(AesEaxKey()), Not(IsOk()));
}

TEST(AesEaxKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(AesEaxKeyManager().ValidateKeyFormat(AesEaxKeyFormat()),
              Not(IsOk()));
}

TEST(AesEaxKeyManagerTest, ValidKeyFormat) {
  AesEaxKeyFormat format;
  format.set_key_size(32);
  format.mutable_params()->set_iv_size(16);
  EXPECT_THAT(AesEaxKeyManager().ValidateKeyFormat(format), IsOk());
}

TEST(AesEaxKeyManagerTest, ValidKeyFormatKeySize) {
  AesEaxKeyFormat format;
  format.mutable_params()->set_iv_size(16);

  for (int len = 0; len < 200; ++len) {
    format.set_key_size(len);
    if (len == 16 || len == 32) {
      EXPECT_THAT(AesEaxKeyManager().ValidateKeyFormat(format), IsOk())
          << "for len = " << len;
    } else {
      EXPECT_THAT(AesEaxKeyManager().ValidateKeyFormat(format), Not(IsOk()))
          << "for len = " << len;
    }
  }
}

TEST(AesEaxKeyManagerTest, ValidKeyFormatIvSize) {
  AesEaxKeyFormat format;
  format.set_key_size(32);

  for (int iv_size = 0; iv_size < 200; ++iv_size) {
    format.mutable_params()->set_iv_size(iv_size);
    if (iv_size == 12 || iv_size == 16) {
      EXPECT_THAT(AesEaxKeyManager().ValidateKeyFormat(format), IsOk())
          << "for iv_size = " << iv_size;
    } else {
      EXPECT_THAT(AesEaxKeyManager().ValidateKeyFormat(format), Not(IsOk()))
          << "for iv_size = " << iv_size;
    }
  }
}

TEST(AesEaxKeyManagerTest, CreateKey) {
  AesEaxKeyFormat format;
  format.set_key_size(32);
  format.mutable_params()->set_iv_size(16);
  auto key_or = AesEaxKeyManager().CreateKey(format);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_value(), SizeIs(format.key_size()));
  EXPECT_THAT(key_or.ValueOrDie().params().iv_size(),
              Eq(format.params().iv_size()));
}

TEST(AesEaxKeyManagerTest, CreateKeyIsValid) {
  AesEaxKeyFormat format;
  format.set_key_size(32);
  format.mutable_params()->set_iv_size(16);
  auto key_or = AesEaxKeyManager().CreateKey(format);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(AesEaxKeyManager().ValidateKey(key_or.ValueOrDie()), IsOk());
}

TEST(AesEaxKeyManagerTest, MultipleCreateCallsCreateDifferentKeys) {
  AesEaxKeyFormat format;
  AesEaxKeyManager manager;
  format.set_key_size(32);
  format.mutable_params()->set_iv_size(16);
  auto key1_or = manager.CreateKey(format);
  ASSERT_THAT(key1_or.status(), IsOk());
  auto key2_or = manager.CreateKey(format);
  ASSERT_THAT(key2_or.status(), IsOk());
  EXPECT_THAT(key1_or.ValueOrDie().key_value(),
              Ne(key2_or.ValueOrDie().key_value()));
}

TEST(AesEaxKeyManagerTest, ValidKey) {
  AesEaxKey key;
  key.set_key_value(std::string(32, 'a'));
  key.mutable_params()->set_iv_size(16);
  EXPECT_THAT(AesEaxKeyManager().ValidateKey(key), IsOk());
}

TEST(AesEaxKeyManagerTest, ValidateKeyKeyLength) {
  AesEaxKey key;
  key.mutable_params()->set_iv_size(16);

  for (int len = 0; len < 200; ++len) {
    key.set_key_value(std::string(len, 'a'));
    if (len == 16 || len == 32) {
      EXPECT_THAT(AesEaxKeyManager().ValidateKey(key), IsOk())
          << "for len = " << len;
    } else {
      EXPECT_THAT(AesEaxKeyManager().ValidateKey(key), Not(IsOk()))
          << "for len = " << len;
    }
  }
}

TEST(AesEaxKeyManagerTest, ValidateKeyIvLength) {
  AesEaxKey key;
  key.set_key_value(std::string(32, 'a'));

  for (int iv_len = 0; iv_len < 200; ++iv_len) {
    key.mutable_params()->set_iv_size(iv_len);
    if (iv_len == 12 || iv_len == 16) {
      EXPECT_THAT(AesEaxKeyManager().ValidateKey(key), IsOk())
          << "for iv_size = " << iv_len;
    } else {
      EXPECT_THAT(AesEaxKeyManager().ValidateKey(key), Not(IsOk()))
          << "for iv_size = " << iv_len;
    }
  }
}

TEST(AesGcmKeyManagerTest, CreateAead) {
  AesEaxKeyFormat format;
  format.set_key_size(32);
  format.mutable_params()->set_iv_size(16);
  StatusOr<AesEaxKey> key_or = AesEaxKeyManager().CreateKey(format);
  ASSERT_THAT(key_or.status(), IsOk());

  StatusOr<std::unique_ptr<Aead>> aead_or =
      AesEaxKeyManager().GetPrimitive<Aead>(key_or.ValueOrDie());

  ASSERT_THAT(aead_or.status(), IsOk());

  StatusOr<std::unique_ptr<Aead>> boring_ssl_aead_or =
      subtle::AesEaxBoringSsl::New(
          util::SecretDataFromStringView(key_or.ValueOrDie().key_value()),
          key_or.ValueOrDie().params().iv_size());
  ASSERT_THAT(boring_ssl_aead_or.status(), IsOk());

  ASSERT_THAT(EncryptThenDecrypt(*aead_or.ValueOrDie(),
                                 *boring_ssl_aead_or.ValueOrDie(),
                                 "message", "aad"),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
