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

#include "tink/aead/kms_envelope_aead_key_manager.h"

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "tink/aead.h"
#include "tink/registry.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "tink/util/test_matchers.h"
#include "gtest/gtest.h"
#include "proto/aes_eax.pb.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using crypto::tink::test::DummyKmsClient;
using google::crypto::tink::AesEaxKey;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::KmsEnvelopeAeadKey;
using google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using google::crypto::tink::KeyData;
using testing::AllOf;
using testing::HasSubstr;

namespace {

class KmsEnvelopeAeadKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string env_aead_key_type_ =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";
};

TEST_F(KmsEnvelopeAeadKeyManagerTest, Basic) {
  KmsEnvelopeAeadKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(KmsEnvelopeAeadKeyManagerTest, KeyDataErrors_BadKeyType) {
  KmsEnvelopeAeadKeyManager key_manager;
  KeyData key_data;
  std::string bad_key_type =
      "type.googleapis.com/google.crypto.tink.SomeOtherKey";
  key_data.set_type_url(bad_key_type);
  auto result = key_manager.GetPrimitive(key_data);
  EXPECT_THAT(result.status(),
      StatusIs(util::error::INVALID_ARGUMENT,
               AllOf(HasSubstr(bad_key_type), HasSubstr("not supported"))));
}

TEST_F(KmsEnvelopeAeadKeyManagerTest, KeyDataErrors_BadKeyValue) {
  KmsEnvelopeAeadKeyManager key_manager;
  KeyData key_data;
  key_data.set_type_url(env_aead_key_type_);
  key_data.set_value("some bad serialized proto");
  auto result = key_manager.GetPrimitive(key_data);
  EXPECT_THAT(result.status(),
      StatusIs(util::error::INVALID_ARGUMENT, HasSubstr("not parse")));
}

TEST_F(KmsEnvelopeAeadKeyManagerTest, KeyDataErrors_BadVersion) {
  KmsEnvelopeAeadKeyManager key_manager;
  KeyData key_data;
  KmsEnvelopeAeadKey key;
  key.set_version(1);
  key_data.set_type_url(env_aead_key_type_);
  key_data.set_value(key.SerializeAsString());
  auto result = key_manager.GetPrimitive(key_data);
  EXPECT_THAT(result.status(),
      StatusIs(util::error::INVALID_ARGUMENT, HasSubstr("version")));
}

TEST_F(KmsEnvelopeAeadKeyManagerTest, KeyMessageErrors_BadProtobuf) {
  KmsEnvelopeAeadKeyManager key_manager;
  AesEaxKey key;
  auto result = key_manager.GetPrimitive(key);
  EXPECT_THAT(result.status(),
      StatusIs(util::error::INVALID_ARGUMENT,
               AllOf(HasSubstr("AesEaxKey"), HasSubstr("not supported"))));
}

TEST_F(KmsEnvelopeAeadKeyManagerTest, Primitives) {
  std::string plaintext = "some plaintext";
  std::string aad = "some aad";

  // Initialize Registry and KmsClients.
  EXPECT_THAT(AeadConfig::Register(), IsOk());
  std::string uri_1_prefix = "prefix1";
  std::string uri_2_prefix = "prefix2";
  std::string uri_1 = absl::StrCat(uri_1_prefix + ":some_uri1");
  std::string uri_2 = absl::StrCat(uri_2_prefix + ":some_uri2");
  auto status = KmsClients::Add(
      absl::make_unique<DummyKmsClient>(uri_1_prefix, uri_1));
  EXPECT_THAT(status, IsOk());
  status = KmsClients::Add(
      absl::make_unique<DummyKmsClient>(uri_2_prefix, ""));
  EXPECT_THAT(status, IsOk());

  KmsEnvelopeAeadKeyManager key_manager;
  KmsEnvelopeAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_kek_uri(uri_1);
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();

  {  // Using key message only.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_THAT(result.status(), IsOk());
    auto envelope_aead = std::move(result.ValueOrDie());
    auto encrypt_result = envelope_aead->Encrypt(plaintext, aad);
    EXPECT_THAT(encrypt_result.status(), IsOk());
    auto ciphertext = encrypt_result.ValueOrDie();
    EXPECT_THAT(ciphertext, HasSubstr(uri_1));
    auto decrypt_result = envelope_aead->Decrypt(ciphertext, aad);
    EXPECT_THAT(decrypt_result.status(), IsOk());
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(env_aead_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_THAT(result.status(), IsOk());
    auto envelope_aead = std::move(result.ValueOrDie());
    auto encrypt_result = envelope_aead->Encrypt(plaintext, aad);
    EXPECT_THAT(encrypt_result.status(), IsOk());
    auto ciphertext = encrypt_result.ValueOrDie();
    EXPECT_THAT(ciphertext, HasSubstr(uri_1));
    auto decrypt_result = envelope_aead->Decrypt(ciphertext, aad);
    EXPECT_THAT(decrypt_result.status(), IsOk());
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }

  {  // Using key message and a KmsClient not bound to a specific key.
    key.mutable_params()->set_kek_uri(uri_2);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_THAT(result.status(), IsOk());
    auto envelope_aead = std::move(result.ValueOrDie());
    auto encrypt_result = envelope_aead->Encrypt(plaintext, aad);
    EXPECT_THAT(encrypt_result.status(), IsOk());
    auto ciphertext = encrypt_result.ValueOrDie();
    EXPECT_THAT(ciphertext, HasSubstr(uri_2));
    auto decrypt_result = envelope_aead->Decrypt(ciphertext, aad);
    EXPECT_THAT(decrypt_result.status(), IsOk());
    EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
  }
}

TEST_F(KmsEnvelopeAeadKeyManagerTest, PrimitivesErrors) {
  // Initialize Registry and KmsClients.
  Registry::Reset();
  std::string uri_1_prefix = "prefix1";
  std::string uri_1 = absl::StrCat(uri_1_prefix + ":some_uri1");
  auto status = KmsClients::Add(
      absl::make_unique<DummyKmsClient>(uri_1_prefix, uri_1));
  EXPECT_THAT(status, IsOk());

  KmsEnvelopeAeadKeyManager key_manager;
  KmsEnvelopeAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_kek_uri(uri_1);
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();

  {  // No KeyManager for DEK template.
    auto result = key_manager.GetPrimitive(key);
    EXPECT_THAT(result.status(),
                StatusIs(util::error::NOT_FOUND,
                         AllOf(HasSubstr("No manager"),
                               HasSubstr("AesEaxKey"))));
  }

  {  // A key with an unknown KEK URI.
    key.mutable_params()->set_kek_uri("some unknown kek uri");
    auto result = key_manager.GetPrimitive(key);
    EXPECT_THAT(result.status(), StatusIs(util::error::NOT_FOUND,
                                          HasSubstr("KmsClient")));
  }
}

TEST_F(KmsEnvelopeAeadKeyManagerTest, NewKeyErrors) {
  KmsEnvelopeAeadKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  {  // Bad key format.
    AesEaxKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_THAT(result.status(),
                StatusIs(util::error::INVALID_ARGUMENT,
                         AllOf(HasSubstr("AesEaxKeyFormat"),
                               HasSubstr("not supported"))));
  }

  {  // Bad serialized key format.
    auto result = key_factory.NewKey("some bad serialized proto");
    EXPECT_THAT(result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                          HasSubstr("not parse")));
  }
}

TEST_F(KmsEnvelopeAeadKeyManagerTest, NewKeyBasic) {
  KmsEnvelopeAeadKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri("some key uri");

  { // Via NewKey(format_proto).
    auto result = key_factory.NewKey(key_format);
    EXPECT_THAT(result.status(), IsOk());
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix_ + key->GetTypeName(), env_aead_key_type_);
    std::unique_ptr<KmsEnvelopeAeadKey> env_aead_key(
        reinterpret_cast<KmsEnvelopeAeadKey*>(key.release()));
    EXPECT_EQ(0, env_aead_key->version());
    EXPECT_EQ(key_format.kek_uri(), env_aead_key->params().kek_uri());
  }

  { // Via NewKey(serialized_format_proto).
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_THAT(result.status(), IsOk());
    auto key = std::move(result.ValueOrDie());
    EXPECT_EQ(key_type_prefix_ + key->GetTypeName(), env_aead_key_type_);
    std::unique_ptr<KmsEnvelopeAeadKey> env_aead_key(
        reinterpret_cast<KmsEnvelopeAeadKey*>(key.release()));
    EXPECT_EQ(0, env_aead_key->version());
    EXPECT_EQ(key_format.kek_uri(), env_aead_key->params().kek_uri());
  }

  { // Via NewKeyData(serialized_format_proto).
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_THAT(result.status(), IsOk());
    auto key_data = std::move(result.ValueOrDie());
    EXPECT_EQ(env_aead_key_type_, key_data->type_url());
    EXPECT_EQ(KeyData::REMOTE, key_data->key_material_type());
    KmsEnvelopeAeadKey env_aead_key;
    EXPECT_TRUE(env_aead_key.ParseFromString(key_data->value()));
    EXPECT_EQ(0, env_aead_key.version());
    EXPECT_EQ(key_format.kek_uri(), env_aead_key.params().kek_uri());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
