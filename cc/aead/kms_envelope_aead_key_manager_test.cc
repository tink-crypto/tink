// Copyright 2019 Google LLC
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

#include "tink/aead/kms_envelope_aead_key_manager.h"

#include <stdlib.h>

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/kms_envelope_aead.h"
#include "tink/config/global_registry.h"
#include "tink/keyset_handle.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/registry.h"
#include "tink/subtle/aead_test_util.h"
#include "tink/util/fake_kms_client.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::DummyKmsClient;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::KmsEnvelopeAeadKey;
using ::google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using ::testing::Eq;
using ::testing::Not;

namespace {

TEST(KmsEnvelopeAeadKeyManagerTest, Basics) {
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().get_version(), Eq(0));
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey"));
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().key_material_type(),
              Eq(google::crypto::tink::KeyData::REMOTE));
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().ValidateKey(KmsEnvelopeAeadKey()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateValidKey) {
  KmsEnvelopeAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_kek_uri("Some uri");
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();

  EXPECT_THAT(KmsEnvelopeAeadKeyManager().ValidateKey(key), IsOk());
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateWrongVersion) {
  KmsEnvelopeAeadKey key;
  key.set_version(1);
  key.mutable_params()->set_kek_uri("Some uri");
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateNoUri) {
  KmsEnvelopeAeadKey key;
  key.set_version(1);
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().ValidateKey(key), Not(IsOk()));
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateKeyFormatEmptyKey) {
  EXPECT_THAT(
      KmsEnvelopeAeadKeyManager().ValidateKeyFormat(KmsEnvelopeAeadKeyFormat()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateKeyFormatValidKey) {
  KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri("Some uri");
  *key_format.mutable_dek_template() = AeadKeyTemplates::Aes128Eax();
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateKeyFormatNoUri) {
  KmsEnvelopeAeadKeyFormat key_format;
  *key_format.mutable_dek_template() = AeadKeyTemplates::Aes128Eax();
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateKeyFormatNoTemplate) {
  KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri("Some uri");
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(KmsEnvelopeAeadKeyManagerTest, ValidateKeyFormatInvalidDekTemplate) {
  KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri("Some uri");
  *key_format.mutable_dek_template() = MacKeyTemplates::HmacSha256();
  EXPECT_THAT(KmsEnvelopeAeadKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(KmsEnvelopeAeadKeyManagerTest, CreateKey) {
  KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri("Some uri");
  *key_format.mutable_dek_template() = AeadKeyTemplates::Aes128Eax();
  auto key_or = KmsEnvelopeAeadKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or, IsOk());
  EXPECT_THAT(key_or.value().params().kek_uri(), Eq(key_format.kek_uri()));
  EXPECT_THAT(key_or.value().params().dek_template().value(),
              Eq(key_format.dek_template().value()));
}

class KmsEnvelopeAeadKeyManagerCreateTest : public ::testing::Test {
 public:
  // The KmsClients class has a global variable which keeps the registered
  // clients. To reflect that in the test, we set them up in the SetUpTestSuite
  // function.
  static void SetUpTestSuite() {
    if (!KmsClients::Add(
             absl::make_unique<DummyKmsClient>("prefix1", "prefix1:some_key1"))
             .ok())
      abort();
    if (!KmsClients::Add(absl::make_unique<DummyKmsClient>("prefix2", "")).ok())
      abort();

    if (!Registry::RegisterKeyTypeManager(absl::make_unique<AesEaxKeyManager>(),
                                          true)
             .ok())
      abort();
  }
};

TEST_F(KmsEnvelopeAeadKeyManagerCreateTest, CreateAead) {
  KmsEnvelopeAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_kek_uri("prefix1:some_key1");
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();

  auto kms_aead = KmsEnvelopeAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead, IsOk());

  auto direct_aead =
      KmsEnvelopeAead::New(key.params().dek_template(),
                           absl::make_unique<DummyAead>("prefix1:some_key1"));
  ASSERT_THAT(direct_aead, IsOk());

  EXPECT_THAT(EncryptThenDecrypt(*kms_aead.value(), *direct_aead.value(),
                                 "plaintext", "aad"),
              IsOk());
}

TEST_F(KmsEnvelopeAeadKeyManagerCreateTest, CreateAeadWrongKeyName) {
  KmsEnvelopeAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_kek_uri("prefix1:some_other_key");
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();

  auto kms_aead = KmsEnvelopeAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead, Not(IsOk()));
}

TEST_F(KmsEnvelopeAeadKeyManagerCreateTest, CreateAeadWrongTypeUrl) {
  KmsEnvelopeAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_kek_uri("prefix1:some_other_key");
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();
  key.mutable_params()->mutable_dek_template()->set_type_url(
      "Some unkonwn type url");

  auto kms_aead = KmsEnvelopeAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead, Not(IsOk()));
}

TEST_F(KmsEnvelopeAeadKeyManagerCreateTest, CreateAeadWrongPrefix) {
  KmsEnvelopeAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_kek_uri("non-existing-prefix:some_key1");
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();

  auto kms_aead = KmsEnvelopeAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead, Not(IsOk()));
}

TEST_F(KmsEnvelopeAeadKeyManagerCreateTest, CreateAeadUnboundKey) {
  KmsEnvelopeAeadKey key;
  key.set_version(0);
  key.mutable_params()->set_kek_uri("prefix2:some_key2");
  *(key.mutable_params()->mutable_dek_template()) =
      AeadKeyTemplates::Aes128Eax();

  auto kms_aead = KmsEnvelopeAeadKeyManager().GetPrimitive<Aead>(key);
  ASSERT_THAT(kms_aead, IsOk());

  auto direct_aead =
      KmsEnvelopeAead::New(key.params().dek_template(),
                           absl::make_unique<DummyAead>("prefix2:some_key2"));
  ASSERT_THAT(direct_aead, IsOk());

  EXPECT_THAT(EncryptThenDecrypt(*kms_aead.value(), *direct_aead.value(),
                                 "plaintext", "aad"),
              IsOk());
}

class KmsEnvelopeAeadKeyManagerDekTemplatesTest
    : public testing::TestWithParam<KeyTemplate> {
  void SetUp() override { ASSERT_THAT(AeadConfig::Register(), IsOk()); }
};

TEST_P(KmsEnvelopeAeadKeyManagerDekTemplatesTest, EncryptDecryp) {
  util::StatusOr<std::string> kek_uri_result =
      test::FakeKmsClient::CreateFakeKeyUri();
  ASSERT_THAT(kek_uri_result, IsOk());
  std::string kek_uri = kek_uri_result.value();
  util::Status register_fake_kms_client_status =
      test::FakeKmsClient::RegisterNewClient(kek_uri, /*credentials_path=*/"");
  ASSERT_THAT(register_fake_kms_client_status, IsOk());

  KeyTemplate dek_template = GetParam();
  KeyTemplate env_template =
      AeadKeyTemplates::KmsEnvelopeAead(kek_uri, dek_template);
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(env_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<Aead>> envelope_aead =
      (*handle)->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(envelope_aead, IsOk());

  std::string plaintext = "plaintext";
  std::string associated_data = "associated_data";
  util::StatusOr<std::string> ciphertext =
      (*envelope_aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  util::StatusOr<std::string> decrypted =
      (*envelope_aead)->Decrypt(ciphertext.value(), associated_data);
  EXPECT_THAT(decrypted, IsOkAndHolds(plaintext));

  std::string invalid_associated_data = "invalid_associated_data";
  util::StatusOr<std::string> decrypted_with_invalid_associated_data =
      (*envelope_aead)->Decrypt(ciphertext.value(), invalid_associated_data);
  EXPECT_THAT(decrypted_with_invalid_associated_data.status(), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    KmsEnvelopeAeadKeyManagerDekTemplatesTest,
    KmsEnvelopeAeadKeyManagerDekTemplatesTest,
    testing::Values(AeadKeyTemplates::Aes128Gcm(),
                    AeadKeyTemplates::Aes256Gcm(),
                    AeadKeyTemplates::Aes128CtrHmacSha256(),
                    AeadKeyTemplates::Aes128Eax(),
                    AeadKeyTemplates::Aes128GcmNoPrefix()));

}  // namespace
}  // namespace tink
}  // namespace crypto
