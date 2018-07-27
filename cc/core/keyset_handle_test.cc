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

#include "tink/keyset_handle.h"

#include "gtest/gtest.h"
#include "tink/aead_key_templates.h"
#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json_keyset_reader.h"
#include "tink/json_keyset_writer.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/config/tink_config.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/keyset_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::KeysetUtil;
using crypto::tink::test::AddLegacyKey;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using crypto::tink::test::DummyAead;

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace {

class KeysetHandleTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto status = TinkConfig::Register();
    ASSERT_TRUE(status.ok()) << status;
  }
};

TEST_F(KeysetHandleTest, testReadEncryptedKeyset_Binary) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  {  // Good encrypted keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = aead.Encrypt(
        keyset.SerializeAsString(), /* associated_data= */ "").ValueOrDie();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(BinaryKeysetReader::New(
        encrypted_keyset.SerializeAsString()).ValueOrDie());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_TRUE(result.ok()) << result.status();
    auto handle = std::move(result.ValueOrDie());
    EXPECT_EQ(keyset.SerializeAsString(),
              KeysetUtil::GetKeyset(*handle).SerializeAsString());
  }

  {  // AEAD does not match the ciphertext
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = aead.Encrypt(
        keyset.SerializeAsString(), /* associated_data= */ "").ValueOrDie();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(BinaryKeysetReader::New(
        encrypted_keyset.SerializeAsString()).ValueOrDie());
    DummyAead wrong_aead("wrong aead");
    auto result = KeysetHandle::Read(std::move(reader), wrong_aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }

  {  // Ciphertext does not contain actual keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = aead.Encrypt(
        "not a serialized keyset", /* associated_data= */ "").ValueOrDie();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(BinaryKeysetReader::New(
        encrypted_keyset.SerializeAsString()).ValueOrDie());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }

  {  // Wrong ciphertext of encrypted keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = "totally wrong ciphertext";
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(BinaryKeysetReader::New(
        encrypted_keyset.SerializeAsString()).ValueOrDie());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }
}

TEST_F(KeysetHandleTest, testReadEncryptedKeyset_Json) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  {  // Good encrypted keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = aead.Encrypt(
        keyset.SerializeAsString(), /* associated_data= */ "").ValueOrDie();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto* keyset_info = encrypted_keyset.mutable_keyset_info();
    keyset_info->set_primary_key_id(42);
    auto* key_info = keyset_info->add_key_info();
    key_info->set_key_id(42);
    key_info->set_type_url("dummy key type");
    key_info->set_output_prefix_type(OutputPrefixType::TINK);
    key_info->set_status(KeyStatusType::ENABLED);
    std::stringbuf buffer;
    std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
    auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
    ASSERT_TRUE(writer_result.ok()) << writer_result.status();
    auto status = writer_result.ValueOrDie()->Write(encrypted_keyset);
    EXPECT_TRUE(status.ok()) << status;
    std::string json_serialized_encrypted_keyset = buffer.str();
    EXPECT_TRUE(status.ok()) << status;
    auto reader = std::move(JsonKeysetReader::New(
        json_serialized_encrypted_keyset).ValueOrDie());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_TRUE(result.ok()) << result.status();
    auto handle = std::move(result.ValueOrDie());
    EXPECT_EQ(keyset.SerializeAsString(),
              KeysetUtil::GetKeyset(*handle).SerializeAsString());
  }

  {  // AEAD does not match the ciphertext
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = aead.Encrypt(
        keyset.SerializeAsString(), /* associated_data= */ "").ValueOrDie();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(JsonKeysetReader::New(
        encrypted_keyset.SerializeAsString()).ValueOrDie());
    DummyAead wrong_aead("wrong aead");
    auto result = KeysetHandle::Read(std::move(reader), wrong_aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }

  {  // Ciphertext does not contain actual keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = aead.Encrypt(
        "not a serialized keyset", /* associated_data= */ "").ValueOrDie();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(JsonKeysetReader::New(
        encrypted_keyset.SerializeAsString()).ValueOrDie());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }

  {  // Wrong ciphertext of encrypted keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = "totally wrong ciphertext";
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(JsonKeysetReader::New(
        encrypted_keyset.SerializeAsString()).ValueOrDie());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }
}

TEST_F(KeysetHandleTest, testWriteEncryptedKeyset_Json) {
  // Prepare a valid keyset handle
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  auto reader = std::move(
      BinaryKeysetReader::New(keyset.SerializeAsString()).ValueOrDie());
  auto keyset_handle = std::move(
      CleartextKeysetHandle::Read(std::move(reader)).ValueOrDie());

  // Prepare a keyset writer.
  DummyAead aead("dummy aead 42");
  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream(new std::ostream(&buffer));
  auto writer = std::move(
      JsonKeysetWriter::New(std::move(destination_stream)).ValueOrDie());

  // Write the keyset handle and check the result.
  auto status = keyset_handle->Write(writer.get(), aead);
  EXPECT_TRUE(status.ok()) << status;
  auto reader_result = JsonKeysetReader::New(buffer.str());
  EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  auto read_encrypted_result = reader_result.ValueOrDie()->ReadEncrypted();
  EXPECT_TRUE(read_encrypted_result.ok()) << read_encrypted_result.status();
  auto encrypted_keyset = std::move(read_encrypted_result.ValueOrDie());
  auto decrypt_result = aead.Decrypt(encrypted_keyset->encrypted_keyset(),
                                     /* associated_data= */ "");
  EXPECT_TRUE(decrypt_result.status().ok()) << decrypt_result.status();
  auto decrypted = decrypt_result.ValueOrDie();
  EXPECT_EQ(decrypted, keyset.SerializeAsString());

  // Try writing to a null-writer.
  status = keyset_handle->Write(nullptr, aead);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, status.error_code());
}

TEST_F(KeysetHandleTest, testGenerateNewKeysetHandle) {
  const google::crypto::tink::KeyTemplate* key_templates[] = {
    &AeadKeyTemplates::Aes128Gcm(),
    &AeadKeyTemplates::Aes256Gcm(),
    &AeadKeyTemplates::Aes128CtrHmacSha256(),
    &AeadKeyTemplates::Aes256CtrHmacSha256(),
  };
  for (auto templ : key_templates) {
    auto handle_result = KeysetHandle::GenerateNew(*templ);
    EXPECT_TRUE(handle_result.ok())
        << "Failed for template:\n " << templ->SerializeAsString()
        << "\n with status: "<< handle_result.status();
  }
}

TEST_F(KeysetHandleTest, testGenerateNewKeysetHandleErrors) {
  KeyTemplate templ;
  templ.set_type_url("type.googleapis.com/some.unknown.KeyType");

  auto handle_result = KeysetHandle::GenerateNew(templ);
  EXPECT_FALSE(handle_result.ok());
  EXPECT_EQ(util::error::NOT_FOUND, handle_result.status().error_code());
}


void CompareKeyMetadata(const Keyset::Key& expected,
                        const Keyset::Key& actual) {
  EXPECT_EQ(expected.status(), actual.status());
  EXPECT_EQ(expected.key_id(), actual.key_id());
  EXPECT_EQ(expected.output_prefix_type(), actual.output_prefix_type());
}

TEST_F(KeysetHandleTest, testGetPublicKeysetHandle) {
  { // A keyset with a single key.
    auto handle_result = KeysetHandle::GenerateNew(
        SignatureKeyTemplates::EcdsaP256());
    ASSERT_TRUE(handle_result.ok()) << handle_result.status();
    auto handle = std::move(handle_result.ValueOrDie());
    auto public_handle_result = handle->GetPublicKeysetHandle();
    ASSERT_TRUE(public_handle_result.ok()) << public_handle_result.status();
    auto keyset = KeysetUtil::GetKeyset(*handle);
    auto public_keyset = KeysetUtil::GetKeyset(
        *(public_handle_result.ValueOrDie()));
    EXPECT_EQ(keyset.primary_key_id(), public_keyset.primary_key_id());
    EXPECT_EQ(keyset.key_size(), public_keyset.key_size());
    CompareKeyMetadata(keyset.key(0), public_keyset.key(0));
    EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC,
              public_keyset.key(0).key_data().key_material_type());
  }
  { // A keyset with multiple keys.
    EcdsaSignKeyManager key_manager;
    const KeyFactory& key_factory = key_manager.get_key_factory();
    Keyset keyset;
    int key_count = 3;

    AddTinkKey(EcdsaSignKeyManager::kKeyType,
               /* key_id= */ 623628,
               *(key_factory.NewKey(
                   SignatureKeyTemplates::EcdsaP256().value()).ValueOrDie()),
               KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PRIVATE,
               &keyset);
    AddLegacyKey(EcdsaSignKeyManager::kKeyType,
                 /* key_id= */ 36285,
                 *(key_factory.NewKey(
                     SignatureKeyTemplates::EcdsaP384().value()).ValueOrDie()),
                 KeyStatusType::DISABLED,
                 KeyData::ASYMMETRIC_PRIVATE,
                 &keyset);
    AddRawKey(EcdsaSignKeyManager::kKeyType,
              /* key_id= */ 42,
              *(key_factory.NewKey(
                  SignatureKeyTemplates::EcdsaP384().value()).ValueOrDie()),
              KeyStatusType::ENABLED,
              KeyData::ASYMMETRIC_PRIVATE,
              &keyset);
    keyset.set_primary_key_id(42);
    auto handle = KeysetUtil::GetKeysetHandle(keyset);
    auto public_handle_result = handle->GetPublicKeysetHandle();
    ASSERT_TRUE(public_handle_result.ok()) << public_handle_result.status();
    auto public_keyset = KeysetUtil::GetKeyset(
        *(public_handle_result.ValueOrDie()));
    EXPECT_EQ(keyset.primary_key_id(), public_keyset.primary_key_id());
    EXPECT_EQ(keyset.key_size(), public_keyset.key_size());
    for (int i = 0; i < key_count; i++) {
      CompareKeyMetadata(keyset.key(i), public_keyset.key(i));
      EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC,
                public_keyset.key(i).key_data().key_material_type());
    }
  }
}


TEST_F(KeysetHandleTest, testGetPublicKeysetHandleErrors) {
  { // A keyset with a single key.
    auto handle_result = KeysetHandle::GenerateNew(
        AeadKeyTemplates::Aes128Eax());
    ASSERT_TRUE(handle_result.ok()) << handle_result.status();
    auto handle = std::move(handle_result.ValueOrDie());
    auto public_handle_result = handle->GetPublicKeysetHandle();
    ASSERT_FALSE(public_handle_result.ok());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "ASYMMETRIC_PRIVATE",
                        public_handle_result.status().error_message());
  }
  { // A keyset with multiple keys.
    EcdsaSignKeyManager key_manager;
    const KeyFactory& key_factory = key_manager.get_key_factory();
    AesGcmKeyManager aead_key_manager;
    const KeyFactory& aead_key_factory = aead_key_manager.get_key_factory();
    Keyset keyset;

    AddTinkKey(EcdsaSignKeyManager::kKeyType,
               /* key_id= */ 623628,
               *(key_factory.NewKey(
                   SignatureKeyTemplates::EcdsaP256().value()).ValueOrDie()),
               KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PRIVATE,
               &keyset);
    AddLegacyKey(AesGcmKeyManager::kKeyType,
                 /* key_id= */ 42,
                 *(aead_key_factory.NewKey(
                     AeadKeyTemplates::Aes128Gcm().value()).ValueOrDie()),
                 KeyStatusType::ENABLED,
                 KeyData::ASYMMETRIC_PRIVATE,  // Intentionally wrong setting.
                 &keyset);
    keyset.set_primary_key_id(42);
    auto handle = KeysetUtil::GetKeysetHandle(keyset);
    auto public_handle_result = handle->GetPublicKeysetHandle();
    ASSERT_FALSE(public_handle_result.ok());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "PrivateKeyFactory",
                        public_handle_result.status().error_message());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
