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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead_key_templates.h"
#include "tink/config/global_registry.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/keyset_handle.h"
#include "tink/proto_keyset_format.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;

using ::crypto::tink::test::IsOk;
using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using testing::Le;
using testing::SizeIs;

namespace crypto {
namespace tink {
namespace {

class BinaryKeysetWriterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(AeadConfig::Register(), IsOk());

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

TEST_F(BinaryKeysetWriterTest, EncryptedKeysetOverhead) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> keysetEncryptionHandle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry());
  ASSERT_THAT(keysetEncryptionHandle, IsOk());
  util::StatusOr<std::unique_ptr<Aead>> keyset_encryption_aead =
      (*keysetEncryptionHandle)->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(keyset_encryption_aead, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<util::SecretData> serialized_keyset =
      SerializeKeysetToProtoKeysetFormat(**handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_keyset, IsOk());
  util::StatusOr<std::string> raw_encrypted_keyset =
      (*keyset_encryption_aead)
          ->Encrypt(util::SecretDataAsStringView(*serialized_keyset), "");
  ASSERT_THAT(raw_encrypted_keyset, IsOk());

  std::stringbuf encrypted_keyset;
  crypto::tink::util::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(
          absl::make_unique<std::ostream>(&encrypted_keyset));
  ASSERT_THAT(writer, IsOk());

  auto status = (*handle)->Write(writer->get(), **keyset_encryption_aead);
  ASSERT_THAT(status, IsOk());

  // encrypted_keyset is a serialized protocol buffer that only contains
  // raw_encrypted_keyset in a field. So it should only be slightly larger than
  // raw_encrypted_keyset.
  EXPECT_THAT(encrypted_keyset.str(),
              SizeIs(Le(raw_encrypted_keyset->size() + 6)));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
