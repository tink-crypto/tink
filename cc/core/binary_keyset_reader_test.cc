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

#include "tink/binary_keyset_reader.h"

#include <iostream>
#include <istream>
#include <sstream>

#include "tink/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/tink.pb.h"

using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

namespace crypto {
namespace tink {
namespace {

class BinaryKeysetReaderTest : public ::testing::Test {
 protected:
  void SetUp() {
    Keyset::Key key;
    AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset_);
    AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset_);
    keyset_.set_primary_key_id(42);
    good_serialized_keyset_ = keyset_.SerializeAsString();
    bad_serialized_keyset_ = "some weird string";

    encrypted_keyset_.set_encrypted_keyset("some ciphertext with keyset");
    auto keyset_info = encrypted_keyset_.mutable_keyset_info();
    keyset_info->set_primary_key_id(42);
    auto key_info = keyset_info->add_key_info();
    key_info->set_type_url("some type_url");
    key_info->set_key_id(42);
    good_serialized_encrypted_keyset_ = encrypted_keyset_.SerializeAsString();
  }

  EncryptedKeyset encrypted_keyset_;
  Keyset keyset_;
  std::string bad_serialized_keyset_;
  std::string good_serialized_keyset_;
  std::string good_serialized_encrypted_keyset_;
};


TEST_F(BinaryKeysetReaderTest, testReaderCreation) {
  {  // Input stream is null.
    std::unique_ptr<std::istream> null_stream(nullptr);
    auto reader_result = BinaryKeysetReader::New(std::move(null_stream));
    EXPECT_FALSE(reader_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              reader_result.status().code());
  }

  {  // Good serialized keyset.
    auto reader_result = BinaryKeysetReader::New(good_serialized_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Stream with good keyset.
    std::unique_ptr<std::istream> good_keyset_stream(new std::stringstream(
        std::string(good_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(good_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Bad serialized keyset.
    auto reader_result = BinaryKeysetReader::New(bad_serialized_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Stream with bad keyset.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }
}

TEST_F(BinaryKeysetReaderTest, testReadFromString) {
  {  // Good string.
    auto reader_result = BinaryKeysetReader::New(good_serialized_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_result = reader->Read();
    EXPECT_TRUE(read_result.ok()) << read_result.status();
    auto keyset = std::move(read_result.ValueOrDie());
    EXPECT_EQ(good_serialized_keyset_, keyset->SerializeAsString());
  }

  {  // Bad string.
    auto reader_result = BinaryKeysetReader::New(bad_serialized_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_result = reader->Read();
    EXPECT_FALSE(read_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, read_result.status().code());
  }
}

TEST_F(BinaryKeysetReaderTest, testReadFromStream) {
  {  // Good stream.
    std::unique_ptr<std::istream> good_keyset_stream(new std::stringstream(
        std::string(good_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(good_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_result = reader->Read();
    EXPECT_TRUE(read_result.ok()) << read_result.status();
    auto keyset = std::move(read_result.ValueOrDie());
    EXPECT_EQ(good_serialized_keyset_, keyset->SerializeAsString());
  }

  {  // Bad stream.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_result = reader->Read();
    EXPECT_FALSE(read_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, read_result.status().code());
  }
}

TEST_F(BinaryKeysetReaderTest, testReadEncryptedFromString) {
  {  // Good string.
    auto reader_result =
        BinaryKeysetReader::New(good_serialized_encrypted_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_TRUE(read_encrypted_result.ok()) << read_encrypted_result.status();
    auto encrypted_keyset = std::move(read_encrypted_result.ValueOrDie());
    EXPECT_EQ(good_serialized_encrypted_keyset_,
              encrypted_keyset->SerializeAsString());
  }

  {  // Bad string.
    auto reader_result = BinaryKeysetReader::New(bad_serialized_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_FALSE(read_encrypted_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              read_encrypted_result.status().code());
  }
}

TEST_F(BinaryKeysetReaderTest, testReadEncryptedFromStream) {
  {  // Good stream.
    std::unique_ptr<std::istream> good_encrypted_keyset_stream(
        new std::stringstream(std::string(good_serialized_encrypted_keyset_),
                              std::ios_base::in));
    auto reader_result =
        BinaryKeysetReader::New(std::move(good_encrypted_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_TRUE(read_encrypted_result.ok()) << read_encrypted_result.status();
    auto encrypted_keyset = std::move(read_encrypted_result.ValueOrDie());
    EXPECT_EQ(good_serialized_encrypted_keyset_,
              encrypted_keyset->SerializeAsString());
  }

  {  // Bad string.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_FALSE(read_encrypted_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              read_encrypted_result.status().code());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
