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

#include "tink/json_keyset_reader.h"

#include <iostream>
#include <istream>
#include <sstream>

#include "absl/strings/escaping.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"


namespace crypto {
namespace tink {

using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::AesGcmKey;
using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::OutputPrefixType;

namespace {

class JsonKeysetReaderTest : public ::testing::Test {
 protected:
  void SetUp() {
    AesGcmKey gcm_key;
    gcm_key.set_key_value("some gcm key value");
    gcm_key.set_version(0);
    std::string gcm_key_base64;
    absl::Base64Escape(gcm_key.SerializeAsString(), &gcm_key_base64);

    AesEaxKey eax_key;
    eax_key.set_key_value("some eax key value");
    eax_key.set_version(0);
    eax_key.mutable_params()->set_iv_size(16);
    std::string eax_key_base64;
    absl::Base64Escape(eax_key.SerializeAsString(), &eax_key_base64);

    AddTinkKey("type.googleapis.com/google.crypto.tink.AesGcmKey",
               42, gcm_key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset_);
    AddRawKey("type.googleapis.com/google.crypto.tink.AesEaxKey",
              711, eax_key, KeyStatusType::ENABLED,
              KeyData::SYMMETRIC, &keyset_);
    keyset_.set_primary_key_id(42);
    good_json_keyset = "{"
           "\"primaryKeyId\": 42,"
           "\"key\": ["
           "  {"
           "    \"keyData\": {"
           "      \"typeUrl\":"
           "        \"type.googleapis.com/google.crypto.tink.AesGcmKey\","
           "      \"keyMaterialType\": \"SYMMETRIC\","
           "      \"value\": \"" + gcm_key_base64 + "\""
           "    },"
           "    \"outputPrefixType\": \"TINK\","
           "    \"keyId\": 42,"
           "    \"status\": \"ENABLED\""
           "  },"
           "  {"
           "    \"keyData\": {"
           "      \"typeUrl\":"
           "        \"type.googleapis.com/google.crypto.tink.AesEaxKey\","
           "      \"keyMaterialType\": \"SYMMETRIC\","
           "      \"value\": \"" + eax_key_base64 + "\""
           "    },"
           "    \"outputPrefixType\": \"RAW\","
           "    \"keyId\": 711,"
           "    \"status\": \"ENABLED\""
           "  }"
           "]}";

    bad_json_keyset = "some weird string";

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
    good_json_encrypted_keyset_ = "{"
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
  }

  EncryptedKeyset encrypted_keyset_;
  Keyset keyset_;
  std::string bad_json_keyset;
  std::string good_json_keyset;
  std::string good_json_encrypted_keyset_;
};


TEST_F(JsonKeysetReaderTest, testReaderCreation) {
  {  // Input stream is null.
    std::unique_ptr<std::istream> null_stream(nullptr);
    auto reader_result = JsonKeysetReader::New(std::move(null_stream));
    EXPECT_FALSE(reader_result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT,
              reader_result.status().error_code());
  }

  {  // Good serialized keyset.
    auto reader_result = JsonKeysetReader::New(good_json_keyset);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Stream with good keyset.
    std::unique_ptr<std::istream> good_keyset_stream(
        new std::stringstream(std::string(good_json_keyset),
                              std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(good_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Bad serialized keyset.
    auto reader_result = JsonKeysetReader::New(bad_json_keyset);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Stream with bad keyset.
    std::unique_ptr<std::istream> bad_keyset_stream(
        new std::stringstream(std::string(bad_json_keyset),
                              std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }
}

TEST_F(JsonKeysetReaderTest, testReadFromString) {
  {  // Good std::string.
    auto reader_result = JsonKeysetReader::New(good_json_keyset);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_result = reader->Read();
    EXPECT_TRUE(read_result.ok()) << read_result.status();
    auto keyset = std::move(read_result.ValueOrDie());
    EXPECT_EQ(keyset_.SerializeAsString(),
              keyset->SerializeAsString());
  }

  {  // Bad std::string.
    auto reader_result = JsonKeysetReader::New(bad_json_keyset);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_result = reader->Read();
    EXPECT_FALSE(read_result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT,
              read_result.status().error_code());
  }
}

TEST_F(JsonKeysetReaderTest, testReadFromStream) {
  {  // Good stream.
    std::unique_ptr<std::istream> good_keyset_stream(
        new std::stringstream(std::string(good_json_keyset),
                              std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(good_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_result = reader->Read();
    EXPECT_TRUE(read_result.ok()) << read_result.status();
    auto keyset = std::move(read_result.ValueOrDie());
    EXPECT_EQ(keyset_.SerializeAsString(),
              keyset->SerializeAsString());
  }

  {  // Bad stream.
    std::unique_ptr<std::istream> bad_keyset_stream(
        new std::stringstream(std::string(bad_json_keyset),
                              std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_result = reader->Read();
    EXPECT_FALSE(read_result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT,
              read_result.status().error_code());
  }
}

TEST_F(JsonKeysetReaderTest, testReadEncryptedFromString) {
  {  // Good std::string.
    auto reader_result =
        JsonKeysetReader::New(good_json_encrypted_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_TRUE(read_encrypted_result.ok()) << read_encrypted_result.status();
    auto encrypted_keyset = std::move(read_encrypted_result.ValueOrDie());
    EXPECT_EQ(encrypted_keyset_.SerializeAsString(),
              encrypted_keyset->SerializeAsString());
  }

  {  // Bad std::string.
    auto reader_result = JsonKeysetReader::New(bad_json_keyset);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_FALSE(read_encrypted_result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT,
              read_encrypted_result.status().error_code());
  }
}

TEST_F(JsonKeysetReaderTest, testReadEncryptedFromStream) {
  {  // Good stream.
    std::unique_ptr<std::istream> good_encrypted_keyset_stream(
        new std::stringstream(std::string(good_json_encrypted_keyset_),
                              std::ios_base::in));
    auto reader_result =
        JsonKeysetReader::New(std::move(good_encrypted_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_TRUE(read_encrypted_result.ok()) << read_encrypted_result.status();
    auto encrypted_keyset = std::move(read_encrypted_result.ValueOrDie());
    EXPECT_EQ(encrypted_keyset_.SerializeAsString(),
              encrypted_keyset->SerializeAsString());
  }

  {  // Bad std::string.
    std::unique_ptr<std::istream> bad_keyset_stream(
        new std::stringstream(std::string(bad_json_keyset),
                              std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.ValueOrDie());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_FALSE(read_encrypted_result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT,
              read_encrypted_result.status().error_code());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
