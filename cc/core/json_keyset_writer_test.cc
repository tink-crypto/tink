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
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/strings/substitute.h"
#include "include/rapidjson/document.h"
#include "include/rapidjson/error/en.h"
#include "tink/json_keyset_reader.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::AesEaxKey;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::EncryptedKeyset;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::HasSubstr;

namespace {

class JsonKeysetWriterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    gcm_key_.set_key_value("some gcm key value");
    gcm_key_.set_version(0);

    eax_key_.set_key_value("some eax key value");
    eax_key_.set_version(0);
    eax_key_.mutable_params()->set_iv_size(16);

    AddTinkKey("type.googleapis.com/google.crypto.tink.AesGcmKey", 42, gcm_key_,
               KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset_);
    AddRawKey("type.googleapis.com/google.crypto.tink.AesEaxKey", 711, eax_key_,
              KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset_);
    keyset_.set_primary_key_id(42);
    std::string json_string =
        absl::Substitute(R"(
      {
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "$0"
               },
               "outputPrefixType":"TINK",
               "keyId":42,
               "status":"ENABLED"
            },
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value":"$1"
               },
               "outputPrefixType":"RAW",
               "keyId":711,
               "status":"ENABLED"
            }
         ]
      })",
                         absl::Base64Escape(gcm_key_.SerializeAsString()),
                         absl::Base64Escape(eax_key_.SerializeAsString()));
    ASSERT_FALSE(good_json_keyset_.Parse(json_string.c_str()).HasParseError());

    std::string enc_keyset = "some ciphertext with keyset";
    encrypted_keyset_.set_encrypted_keyset(enc_keyset);
    std::string enc_keyset_base64;
    absl::Base64Escape(enc_keyset, &enc_keyset_base64);
    auto keyset_info = encrypted_keyset_.mutable_keyset_info();
    keyset_info->set_primary_key_id(42);
    auto key_info = keyset_info->add_key_info();
    key_info->set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
    key_info->set_key_id(42);
    key_info->set_output_prefix_type(OutputPrefixType::TINK);
    key_info->set_status(KeyStatusType::ENABLED);
    good_json_encrypted_keyset_string_ = "{"
           "\"encryptedKeyset\": \"" + enc_keyset_base64 + "\", "
           "\"keysetInfo\": {"
           "  \"primaryKeyId\": 42,"
           "  \"keyInfo\": ["
           "    {"
           "      \"typeUrl\":"
           "        \"type.googleapis.com/google.crypto.tink.AesGcmKey\","
           "      \"outputPrefixType\": \"TINK\","
           "      \"keyId\": 42,"
           "      \"status\": \"ENABLED\""
           "    }"
           "  ]"
           "}}";
    ASSERT_FALSE(good_json_encrypted_keyset_.Parse(
        good_json_encrypted_keyset_string_.c_str()).HasParseError());
  }

  EncryptedKeyset encrypted_keyset_;
  Keyset keyset_;
  rapidjson::Document good_json_keyset_;
  rapidjson::Document good_json_encrypted_keyset_;
  std::string good_json_encrypted_keyset_string_;
  AesGcmKey gcm_key_;
  AesEaxKey eax_key_;
};

TEST_F(JsonKeysetWriterTest, testWriterCreation) {
  {  // Input stream is null.
    std::unique_ptr<std::ostream> null_stream(nullptr);
    auto writer_result = JsonKeysetWriter::New(std::move(null_stream));
    EXPECT_FALSE(writer_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              writer_result.status().code());
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
  rapidjson::Document json_keyset(rapidjson::kObjectType);
  EXPECT_FALSE(json_keyset.Parse(buffer.str().c_str()).HasParseError());
  EXPECT_TRUE(good_json_keyset_ == json_keyset);
}

TEST_F(JsonKeysetWriterTest, testWriteAndReadKeyset) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.ValueOrDie());
  auto status = writer->Write(keyset_);
  EXPECT_TRUE(status.ok()) << status;

  auto reader_result = JsonKeysetReader::New(buffer.str());
  EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  auto reader = std::move(reader_result.ValueOrDie());
  auto read_result = reader->Read();
  EXPECT_TRUE(read_result.ok()) << read_result.status();
  auto keyset = std::move(read_result.ValueOrDie());
  EXPECT_EQ(keyset_.SerializeAsString(), keyset->SerializeAsString());
}

TEST_F(JsonKeysetWriterTest, testWriteEncryptedKeyset) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.ValueOrDie());
  auto status = writer->Write(encrypted_keyset_);
  EXPECT_TRUE(status.ok()) << status;
  rapidjson::Document json_encrypted_keyset(rapidjson::kObjectType);
  EXPECT_FALSE(
      json_encrypted_keyset.Parse(buffer.str().c_str()).HasParseError())
      << "Parsing error at position "
      << static_cast<unsigned>(json_encrypted_keyset.GetErrorOffset())
      << " of JSON string\n"
      << buffer.str() << "\n"
      << rapidjson::GetParseError_En(json_encrypted_keyset.GetParseError());
  EXPECT_TRUE(good_json_encrypted_keyset_ == json_encrypted_keyset)
      << "Expected JSON:\n" << good_json_encrypted_keyset_string_ << "\n"
      << "Got JSON:\n" << buffer.str();
}

TEST_F(JsonKeysetWriterTest, testWriteAndReadEncryptedKeyset) {
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.ValueOrDie());
  auto status = writer->Write(encrypted_keyset_);
  EXPECT_TRUE(status.ok()) << status;

  auto reader_result = JsonKeysetReader::New(buffer.str());
  EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  auto reader = std::move(reader_result.ValueOrDie());
  auto read_result = reader->ReadEncrypted();
  EXPECT_TRUE(read_result.ok()) << read_result.status();
  auto encrypted_keyset = std::move(read_result.ValueOrDie());
  EXPECT_EQ(encrypted_keyset_.SerializeAsString(),
            encrypted_keyset->SerializeAsString());
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
    EXPECT_EQ(absl::StatusCode::kUnknown, status.code());
  }
  {  // Write encrypted keyset.
    auto status = writer->Write(encrypted_keyset_);
    EXPECT_FALSE(status.ok()) << status;
    EXPECT_EQ(absl::StatusCode::kUnknown, status.code());
  }
}

TEST_F(JsonKeysetWriterTest, WriteLargeKeyId) {
  Keyset keyset;
  AddTinkKey("type.googleapis.com/google.crypto.tink.AesGcmKey", 4123456789,
             gcm_key_, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(4123456789);  // 4123456789 > 2^31

  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer_result.status(), IsOk());
  auto writer = std::move(writer_result.ValueOrDie());
  ASSERT_THAT(writer->Write(keyset), IsOk());
  EXPECT_THAT(buffer.str(), HasSubstr("\"primaryKeyId\": 4123456789"));
  EXPECT_THAT(buffer.str(), HasSubstr("\"keyId\": 4123456789"));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
