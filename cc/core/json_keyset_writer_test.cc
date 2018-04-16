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

#include "tink/json_keyset_writer.h"

#include <ostream>
#include <sstream>

#include "tink/util/protobuf_helper.h"
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

class JsonKeysetWriterTest : public ::testing::Test {
 protected:
  void SetUp() {
    portable_proto::util::JsonPrintOptions json_options;
    json_options.add_whitespace = true;
    json_options.always_print_primitive_fields = true;

    Keyset::Key key;
    AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset_);
    AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset_);
    keyset_.set_primary_key_id(42);
    auto status = portable_proto::util::MessageToJsonString(
        keyset_, &json_keyset_, json_options);
    ASSERT_TRUE(status.ok()) << status;


    encrypted_keyset_.set_encrypted_keyset("some ciphertext with keyset");
    auto keyset_info = encrypted_keyset_.mutable_keyset_info();
    keyset_info->set_primary_key_id(42);
    auto key_info = keyset_info->add_key_info();
    key_info->set_type_url("some type_url");
    key_info->set_key_id(42);
    status = portable_proto::util::MessageToJsonString(
        encrypted_keyset_, &json_encrypted_keyset_, json_options);
    ASSERT_TRUE(status.ok()) << status;
  }

  EncryptedKeyset encrypted_keyset_;
  Keyset keyset_;
  std::string json_keyset_;
  std::string json_encrypted_keyset_;
};

TEST_F(JsonKeysetWriterTest, testWriterCreation) {
  {  // Input stream is null.
    std::unique_ptr<std::ostream> null_stream(nullptr);
    auto writer_result = JsonKeysetWriter::New(std::move(null_stream));
    EXPECT_FALSE(writer_result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT,
              writer_result.status().error_code());
  }

  {  // Stream with good keyset.
    std::unique_ptr<std::ostream> destination_stream(new std::stringstream());
    auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
    EXPECT_TRUE(writer_result.ok()) << writer_result.status();
  }
}

TEST_F(JsonKeysetWriterTest, testWriteKeyset) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.ValueOrDie());
  auto status = writer->Write(keyset_);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(json_keyset_, buffer.str());
}

TEST_F(JsonKeysetWriterTest, testWriteEncryptedKeyset) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.ValueOrDie());
  auto status = writer->Write(encrypted_keyset_);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(json_encrypted_keyset_, buffer.str());
}

TEST_F(JsonKeysetWriterTest, testDestinationStreamErrors) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  destination_stream->setstate(std::ostream::badbit);
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.ValueOrDie());
  {  // Write keyset.
    auto status = writer->Write(keyset_);
    EXPECT_FALSE(status.ok()) << status;
    EXPECT_EQ(util::error::UNKNOWN, status.error_code());
  }
  {  // Write encrypted keyset.
    auto status = writer->Write(encrypted_keyset_);
    EXPECT_FALSE(status.ok()) << status;
    EXPECT_EQ(util::error::UNKNOWN, status.error_code());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
