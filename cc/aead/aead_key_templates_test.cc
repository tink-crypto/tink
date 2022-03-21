// Copyright 2018 Google LLC
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

#include "tink/aead/aead_key_templates.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/kms_envelope_aead.h"
#include "tink/aead/kms_envelope_aead_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/core/key_manager_impl.h"
#include "tink/keyset_handle.h"
#include "tink/subtle/aead_test_util.h"
#include "tink/util/fake_kms_client.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

using google::crypto::tink::AesCtrHmacAeadKeyFormat;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::AesGcmSivKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::Ref;

TEST(AeadKeyTemplatesTest, testAesEaxKeyTemplates) {
  std::string type_url = "type.googleapis.com/google.crypto.tink.AesEaxKey";

  {  // Test Aes128Eax().
    // Check that returned template is correct.
    const KeyTemplate& key_template = AeadKeyTemplates::Aes128Eax();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesEaxKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(16, key_format.key_size());
    EXPECT_EQ(16, key_format.params().iv_size());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = AeadKeyTemplates::Aes128Eax();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesEaxKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Aead>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager->get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test Aes256Eax().
    // Check that returned template is correct.
    const KeyTemplate& key_template = AeadKeyTemplates::Aes256Eax();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesEaxKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(32, key_format.key_size());
    EXPECT_EQ(16, key_format.params().iv_size());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = AeadKeyTemplates::Aes256Eax();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesEaxKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Aead>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager->get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

TEST(Aes128GcmNoPrefix, Basics) {
  EXPECT_THAT(AeadKeyTemplates::Aes128GcmNoPrefix().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(AeadKeyTemplates::Aes128GcmNoPrefix().type_url(),
              Eq(AesGcmKeyManager().get_key_type()));
}

TEST(Aes128GcmNoPrefix, OutputPrefixType) {
  EXPECT_THAT(AeadKeyTemplates::Aes128GcmNoPrefix().output_prefix_type(),
              Eq(OutputPrefixType::RAW));
}

TEST(Aes128GcmNoPrefix, MultipleCallsSameReference) {
  EXPECT_THAT(AeadKeyTemplates::Aes128GcmNoPrefix(),
              Ref(AeadKeyTemplates::Aes128GcmNoPrefix()));
}

TEST(Aes128GcmNoPrefix, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes128GcmNoPrefix();
  AesGcmKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(Aes128GcmNoPrefix, CheckValues) {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes128GcmNoPrefix();
  AesGcmKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(16));
}

TEST(Aes256GcmNoPrefix, Basics) {
  EXPECT_THAT(AeadKeyTemplates::Aes256GcmNoPrefix().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(AeadKeyTemplates::Aes256GcmNoPrefix().type_url(),
              Eq(AesGcmKeyManager().get_key_type()));
}

TEST(Aes256GcmNoPrefix, OutputPrefixType) {
  EXPECT_THAT(AeadKeyTemplates::Aes256GcmNoPrefix().output_prefix_type(),
              Eq(OutputPrefixType::RAW));
}

TEST(Aes256GcmNoPrefix, MultipleCallsSameReference) {
  EXPECT_THAT(AeadKeyTemplates::Aes256GcmNoPrefix(),
              Ref(AeadKeyTemplates::Aes256GcmNoPrefix()));
}

TEST(Aes256GcmNoPrefix, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes256GcmNoPrefix();
  AesGcmKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(Aes256GcmNoPrefix, CheckValues) {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes256GcmNoPrefix();
  AesGcmKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(32));
}

TEST(Aes256Gcm, Basics) {
  EXPECT_THAT(AeadKeyTemplates::Aes256Gcm().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(AeadKeyTemplates::Aes256Gcm().type_url(),
              Eq(AesGcmKeyManager().get_key_type()));
}

TEST(Aes256Gcm, OutputPrefixType) {
  EXPECT_THAT(AeadKeyTemplates::Aes256Gcm().output_prefix_type(),
              Eq(OutputPrefixType::TINK));
}

TEST(Aes256Gcm, MultipleCallsSameReference) {
  EXPECT_THAT(AeadKeyTemplates::Aes256Gcm(),
              Ref(AeadKeyTemplates::Aes256Gcm()));
}

TEST(Aes256Gcm, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes256Gcm();
  AesGcmKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(Aes256Gcm, CheckValues) {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes256Gcm();
  AesGcmKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(32));
}

TEST(Aes128Gcm, Basics) {
  EXPECT_THAT(AeadKeyTemplates::Aes128Gcm().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(AeadKeyTemplates::Aes128Gcm().type_url(),
              Eq(AesGcmKeyManager().get_key_type()));
}

TEST(Aes128Gcm, OutputPrefixType) {
  EXPECT_THAT(AeadKeyTemplates::Aes128Gcm().output_prefix_type(),
              Eq(OutputPrefixType::TINK));
}

TEST(Aes128Gcm, MultipleCallsSameReference) {
  EXPECT_THAT(AeadKeyTemplates::Aes128Gcm(),
              Ref(AeadKeyTemplates::Aes128Gcm()));
}

TEST(Aes128Gcm, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes128Gcm();
  AesGcmKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesGcmKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(Aes128Gcm, CheckValues) {
  const KeyTemplate& key_template = AeadKeyTemplates::Aes128Gcm();
  AesGcmKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(16));
}

TEST(AeadKeyTemplatesTest, testAesGcmSivKeyTemplates) {
  std::string type_url = "type.googleapis.com/google.crypto.tink.AesGcmSivKey";

  {  // Test Aes128GcmSiv().
    // Check that returned template is correct.
    const KeyTemplate& key_template = AeadKeyTemplates::Aes128GcmSiv();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesGcmSivKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(16, key_format.key_size());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = AeadKeyTemplates::Aes128GcmSiv();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesGcmSivKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Aead>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager->get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test Aes256GcmSiv().
    // Check that returned template is correct.
    const KeyTemplate& key_template = AeadKeyTemplates::Aes256GcmSiv();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesGcmSivKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(32, key_format.key_size());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = AeadKeyTemplates::Aes256GcmSiv();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesGcmSivKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Aead>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager->get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

TEST(AeadKeyTemplatesTest, testAesCtrHmacAeadKeyTemplates) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

  {  // Test Aes128CtrHmacSha256().
    // Check that returned template is correct.
    const KeyTemplate& key_template = AeadKeyTemplates::Aes128CtrHmacSha256();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesCtrHmacAeadKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(16, key_format.aes_ctr_key_format().key_size());
    EXPECT_EQ(16, key_format.aes_ctr_key_format().params().iv_size());
    EXPECT_EQ(32, key_format.hmac_key_format().key_size());
    EXPECT_EQ(16, key_format.hmac_key_format().params().tag_size());
    EXPECT_EQ(HashType::SHA256, key_format.hmac_key_format().params().hash());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = AeadKeyTemplates::Aes128CtrHmacSha256();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesCtrHmacAeadKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Aead>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager->get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test Aes256CtrHmacSha256().
    // Check that returned template is correct.
    const KeyTemplate& key_template = AeadKeyTemplates::Aes256CtrHmacSha256();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesCtrHmacAeadKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(32, key_format.aes_ctr_key_format().key_size());
    EXPECT_EQ(16, key_format.aes_ctr_key_format().params().iv_size());
    EXPECT_EQ(32, key_format.hmac_key_format().key_size());
    EXPECT_EQ(32, key_format.hmac_key_format().params().tag_size());
    EXPECT_EQ(HashType::SHA256, key_format.hmac_key_format().params().hash());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = AeadKeyTemplates::Aes256CtrHmacSha256();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesCtrHmacAeadKeyManager key_type_manager;
    auto key_manager = internal::MakeKeyManager<Aead>(&key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager->get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

TEST(AeadKeyTemplatesTest, testXChaCha20Poly1305KeyTemplates) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";

  // Check that returned template is correct.
  const KeyTemplate& key_template = AeadKeyTemplates::XChaCha20Poly1305();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 = AeadKeyTemplates::XChaCha20Poly1305();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the template works with the key manager.
  XChaCha20Poly1305KeyManager key_type_manager;
  auto key_manager = internal::MakeKeyManager<Aead>(&key_type_manager);
  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  auto new_key_result =
      key_manager->get_key_factory().NewKey(key_template.value());
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

TEST(AeadKeyTemplatesTest, testKmsEnvelopeAead) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";
  std::string kek_uri = "foo/bar";
  const KeyTemplate& dek_template = AeadKeyTemplates::Aes128Gcm();

  // Check that returned template is correct.
  const KeyTemplate& key_template =
      AeadKeyTemplates::KmsEnvelopeAead(kek_uri, dek_template);
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::RAW, key_template.output_prefix_type());

  KmsEnvelopeAeadKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(kek_uri, key_format.kek_uri());
  EXPECT_EQ(dek_template.type_url(), key_format.dek_template().type_url());
  EXPECT_EQ(dek_template.value(), key_format.dek_template().value());

  // Check that the template works with the key manager.
  KmsEnvelopeAeadKeyManager key_type_manager;
  auto key_manager = internal::MakeKeyManager<Aead>(&key_type_manager);
  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  auto new_key_result =
      key_manager->get_key_factory().NewKey(key_template.value());
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

TEST(AeadKeyTemplatesTest, testKmsEnvelopeAeadMultipleKeysSameKek) {
  // Initialize the registry.
  ASSERT_TRUE(AeadConfig::Register().ok());

  auto kek_uri_result = test::FakeKmsClient::CreateFakeKeyUri();
  EXPECT_TRUE(kek_uri_result.ok()) << kek_uri_result.status();
  std::string kek_uri = kek_uri_result.value();
  auto register_fake_kms_client_status = test::FakeKmsClient::RegisterNewClient(
      kek_uri, /* credentials_path= */ "");

  std::string type_url =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";
  const KeyTemplate& dek_template = AeadKeyTemplates::Aes128Gcm();

  const KeyTemplate& key_template1 =
      AeadKeyTemplates::KmsEnvelopeAead(kek_uri, dek_template);
  auto handle_result1 = KeysetHandle::GenerateNew(key_template1);
  EXPECT_TRUE(handle_result1.ok());
  auto handle1 = std::move(handle_result1.value());
  auto aead_result1 = handle1->GetPrimitive<Aead>();
  EXPECT_TRUE(aead_result1.ok());
  auto aead1 = std::move(aead_result1.value());

  const KeyTemplate& key_template2 =
      AeadKeyTemplates::KmsEnvelopeAead(kek_uri, dek_template);
  auto handle_result2 = KeysetHandle::GenerateNew(key_template2);
  EXPECT_TRUE(handle_result2.ok());
  auto handle2 = std::move(handle_result2.value());
  auto aead_result2 = handle2->GetPrimitive<Aead>();
  EXPECT_TRUE(aead_result2.ok());
  auto aead2 = std::move(aead_result2.value());

  EXPECT_THAT(EncryptThenDecrypt(*aead1, *aead2, "message", "aad"), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
