// Copyright 2018 Google Inc.
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

#include "tink/binary_keyset_writer.h"

#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tink/util/test_util.h"
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

class BinaryKeysetWriterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Keyset::Key key;
    AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset_);
    AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset_);
    keyset_.set_primary_key_id(42);
    binary_keyset_ = keyset_.SerializeAsString();


    encrypted_keyset_.set_encrypted_keyset("some ciphertext with keyset");
    auto keyset_info = encrypted_keyset_.mutable_keyset_info();
    keyset_info->set_primary_key_id(42);
    auto key_info = keyset_info->add_key_info();
    key_info->set_type_url("some type_url");
    key_info->set_key_id(42);
    binary_encrypted_keyset_ = encrypted_keyset_.SerializeAsString();
  }

  EncryptedKeyset encrypted_keyset_;
  Keyset keyset_;
  std::string binary_keyset_;
  std::string binary_encrypted_keyset_;
};

TEST_F(BinaryKeysetWriterTest, testWriterCreation) {
  {  // Input stream is null.
    std::unique_ptr<std::ostream> null_stream(nullptr);
    auto writer_result = BinaryKeysetWriter::New(std::move(null_stream));
    EXPECT_FALSE(writer_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              writer_result.status().code());
  }

  {  // Stream with good keyset.
    std::unique_ptr<std::ostream> destination_stream(new std::stringstream());
    auto writer_result = BinaryKeysetWriter::New(std::move(destination_stream));
    EXPECT_TRUE(writer_result.ok()) << writer_result.status();
  }
}

TEST_F(BinaryKeysetWriterTest, testWriteKeyset) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer_result = BinaryKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.value());
  auto status = writer->Write(keyset_);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(binary_keyset_, buffer.str());
}

TEST_F(BinaryKeysetWriterTest, testWriteEncryptedKeyset) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer_result = BinaryKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.value());
  auto status = writer->Write(encrypted_keyset_);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(binary_encrypted_keyset_, buffer.str());
}

TEST_F(BinaryKeysetWriterTest, testDestinationStreamErrors) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  destination_stream->setstate(std::ostream::badbit);
  auto writer_result = BinaryKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.value());
  {  // Write keyset.
    auto status = writer->Write(keyset_);
    EXPECT_FALSE(status.ok()) << status;
    EXPECT_EQ(absl::StatusCode::kUnknown, status.code());
  }
  {  // Write encrypted keyset.
    auto status = writer->Write(encrypted_keyset_);
    EXPECT_FALSE(status.ok()) << status;
    EXPECT_EQ(absl::StatusCode::kUnknown, status.code());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
