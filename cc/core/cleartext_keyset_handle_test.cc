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

#include "cc/cleartext_keyset_handle.h"

#include <istream>

#include "cc/keyset_handle.h"
#include "cc/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/tink.pb.h"

using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;

using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

namespace crypto {
namespace tink {
namespace {

class CleartextKeysetHandleTest : public ::testing::Test {
};

TEST_F(CleartextKeysetHandleTest, testFromKeysetProto) {
  Keyset keyset;
  auto result = CleartextKeysetHandle::New(keyset);
  EXPECT_TRUE(result.ok()) << result.status();
}

TEST_F(CleartextKeysetHandleTest, testFromString) {
  {  // Bad serialization.
    auto result = CleartextKeysetHandle::ParseFrom("bad serialized keyset");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }
  {  // Empty serialization.
    auto result = CleartextKeysetHandle::ParseFrom("");
    EXPECT_TRUE(result.ok()) << result.status();
    Keyset keyset;
    EXPECT_EQ(keyset.DebugString(),
              result.ValueOrDie()->get_keyset().DebugString());
  }
  {  // Correct serialization.
    Keyset keyset;
    Keyset::Key key;
    AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset);
    AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset);

    auto result = CleartextKeysetHandle::ParseFrom(keyset.SerializeAsString());
    EXPECT_TRUE(result.ok()) << result.status();
    EXPECT_EQ(keyset.DebugString(),
              result.ValueOrDie()->get_keyset().DebugString());
  }
}

TEST_F(CleartextKeysetHandleTest, testFromStream) {
  {  // Bad serialization.
    std::istringstream stream("some bad serialized keyset");
    auto result = CleartextKeysetHandle::ParseFrom(&stream);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }
  {  // Empty serialization.
    std::istringstream stream("");
    auto result = CleartextKeysetHandle::ParseFrom(&stream);
    EXPECT_TRUE(result.ok()) << result.status();
    Keyset keyset;
    EXPECT_EQ(keyset.DebugString(),
              result.ValueOrDie()->get_keyset().DebugString());
  }
  {  // Correct serialization.
    Keyset keyset;
    Keyset::Key key;
    AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset);
    AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset);

    std::istringstream stream(keyset.SerializeAsString());
    auto result = CleartextKeysetHandle::ParseFrom(&stream);
    EXPECT_TRUE(result.ok()) << result.status();
    EXPECT_EQ(keyset.DebugString(),
              result.ValueOrDie()->get_keyset().DebugString());
  }
}


}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
