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

#include "cc/binary_keyset_reader.h"
#include "cc/keyset_handle.h"
#include "cc/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/tink.pb.h"

using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;

using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {
namespace {

class CleartextKeysetHandleTest : public ::testing::Test {
};

TEST_F(CleartextKeysetHandleTest, testRead) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  {  // Reader that reads a valid keyset.
    auto reader = std::move(
        BinaryKeysetReader::New(keyset.SerializeAsString()).ValueOrDie());
    auto result = CleartextKeysetHandle::Read(std::move(reader));
    EXPECT_TRUE(result.ok()) << result.status();
    auto handle = std::move(result.ValueOrDie());
    EXPECT_EQ(keyset.SerializeAsString(),
              handle->get_keyset().SerializeAsString());
  }

  {  // Reader that fails upon read.
    auto reader = std::move(
        BinaryKeysetReader::New("invalid serialized keyset").ValueOrDie());
    auto result = CleartextKeysetHandle::Read(std::move(reader));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }
}


}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
