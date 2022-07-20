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

#include "tink/cleartext_keyset_handle.h"

#include <istream>
#include <memory>
#include <ostream>
#include <sstream>
#include <utility>

#include "gtest/gtest.h"
#include "tink/binary_keyset_reader.h"
#include "tink/keyset_handle.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;

using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;


namespace crypto {
namespace tink {
namespace {

class CleartextKeysetHandleTest : public ::testing::Test {
 protected:
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
    auto reader =
        std::move(BinaryKeysetReader::New(keyset.SerializeAsString()).value());
    auto result = CleartextKeysetHandle::Read(std::move(reader));
    EXPECT_TRUE(result.ok()) << result.status();
    auto handle = std::move(result.value());
    EXPECT_EQ(keyset.SerializeAsString(),
              TestKeysetHandle::GetKeyset(*handle).SerializeAsString());
  }

  {  // Reader that fails upon read.
    auto reader =
        std::move(BinaryKeysetReader::New("invalid serialized keyset").value());
    auto result = CleartextKeysetHandle::Read(std::move(reader));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  }
}

TEST_F(CleartextKeysetHandleTest, testWrite) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  auto handle = TestKeysetHandle::GetKeysetHandle(keyset);

  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer =
      test::DummyKeysetWriter::New(std::move(destination_stream)).value();

  // Write a valid keyset.
  EXPECT_EQ(CleartextKeysetHandle::Write(writer.get(), *(handle.get())),
            util::OkStatus());

  // Null writer.
  EXPECT_NE(CleartextKeysetHandle::Write(nullptr, *(handle.get())),
            util::OkStatus());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
