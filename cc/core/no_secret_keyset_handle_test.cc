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
#include "tink/no_secret_keyset_handle.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "tink/util/keyset_util.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;

namespace crypto {
namespace tink {
namespace {

TEST(NoSecretKeysetHandleTest, Read) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
            KeyData::REMOTE, &keyset);
  keyset.set_primary_key_id(42);
  auto keyset_result = NoSecretKeysetHandle::Get(keyset);
  ASSERT_THAT(keyset_result.status(), IsOk());
  std::unique_ptr<KeysetHandle>& keyset_handle = keyset_result.ValueOrDie();

  const Keyset& result = CleartextKeysetHandle::GetKeyset(*keyset_handle);
  // We check that result equals keyset. For lack of a better method we do this
  // by hand.
  EXPECT_EQ(result.primary_key_id(), keyset.primary_key_id());
  ASSERT_EQ(result.key_size(), keyset.key_size());
  ASSERT_EQ(result.key(0).key_id(), keyset.key(0).key_id());
  ASSERT_EQ(result.key(1).key_id(), keyset.key(1).key_id());
}

TEST(NoSecretKeysetHandleTest, FailForTypeUnknown) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::UNKNOWN_KEYMATERIAL, &keyset);
  keyset.set_primary_key_id(42);
  auto keyset_result = NoSecretKeysetHandle::Get(keyset);
  EXPECT_THAT(keyset_result.status(),
              StatusIs(util::error::FAILED_PRECONDITION));
}

TEST(NoSecretKeysetHandleTest, FailForTypeSymmetric) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  auto keyset_result = NoSecretKeysetHandle::Get(keyset);
  EXPECT_THAT(keyset_result.status(),
              StatusIs(util::error::FAILED_PRECONDITION));
}

TEST(NoSecretKeysetHandleTest, FailForTypeAssymmetricPrivate) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PRIVATE, &keyset);
  keyset.set_primary_key_id(42);
  auto keyset_result = NoSecretKeysetHandle::Get(keyset);
  EXPECT_THAT(keyset_result.status(),
              StatusIs(util::error::FAILED_PRECONDITION));
}

TEST(NoSecretKeysetHandleTest, FailForHidden) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddTinkKey(absl::StrCat("more key type", i), i, key, KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }
  AddRawKey("some other key type", 10, key, KeyStatusType::ENABLED,
            KeyData::ASYMMETRIC_PRIVATE, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddRawKey(absl::StrCat("more key type", i + 100), i+100, key,
              KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }

  keyset.set_primary_key_id(42);
  auto keyset_result = NoSecretKeysetHandle::Get(keyset);
  EXPECT_THAT(keyset_result.status(),
              StatusIs(util::error::FAILED_PRECONDITION));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
