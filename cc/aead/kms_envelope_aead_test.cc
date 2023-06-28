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

#include "tink/aead/kms_envelope_aead.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/internal/endian.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/keyset_handle.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "tink/internal/ssl_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::Aead;
using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::Test;

constexpr int kEncryptedDekPrefixSize = 4;
constexpr absl::string_view kRemoteAeadName = "kms-backed-aead";

class KmsEnvelopeAeadTest : public Test {
 protected:
  void TearDown() override { Registry::Reset(); }
};

TEST_F(KmsEnvelopeAeadTest, EncryptDecryptSucceed) {
  ASSERT_THAT(AeadConfig::Register(), IsOk());

  // Use an AES-128-GCM primitive as the remote one.
  util::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm());
  ASSERT_THAT(keyset_handle, IsOk());
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Eax();
  util::StatusOr<std::unique_ptr<Aead>> remote_aead =
      (*keyset_handle)->GetPrimitive<Aead>();

  util::StatusOr<std::unique_ptr<Aead>> envelope_aead =
      KmsEnvelopeAead::New(dek_template, *std::move(remote_aead));
  ASSERT_THAT(envelope_aead, IsOk());

  std::string message = "Some data to encrypt.";
  std::string aad = "Some associated data.";
  util::StatusOr<std::string> encrypt_result =
      (*envelope_aead)->Encrypt(message, aad);
  ASSERT_THAT(encrypt_result, IsOk());
  util::StatusOr<std::string> decrypt_result =
      (*envelope_aead)->Decrypt(encrypt_result.value(), aad);
  EXPECT_THAT(decrypt_result, IsOkAndHolds(message));
}

TEST_F(KmsEnvelopeAeadTest, NewFailsIfReamoteAeadIsNull) {
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Eax();
  EXPECT_THAT(
      KmsEnvelopeAead::New(dek_template, /*remote_aead=*/nullptr).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
}

TEST_F(KmsEnvelopeAeadTest, NewFailsIfDekKeyManagerIsNotRegistered) {
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Eax();
  auto remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  EXPECT_THAT(
      KmsEnvelopeAead::New(dek_template, std::move(remote_aead)).status(),
      StatusIs(absl::StatusCode::kNotFound, HasSubstr("AesEaxKey")));
}

TEST_F(KmsEnvelopeAeadTest, NewFailsIfUsingDekTemplateOfUnsupportedKeyType) {
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  KeyTemplate dek_template = MacKeyTemplates::HmacSha256();
  auto remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  EXPECT_THAT(
      KmsEnvelopeAead::New(dek_template, std::move(remote_aead)).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("unsupported key type")));
}

TEST_F(KmsEnvelopeAeadTest, DecryptFailsWithInvalidCiphertextOrAad) {
  ASSERT_THAT(AeadConfig::Register(), IsOk());

  KeyTemplate dek_template = AeadKeyTemplates::Aes128Gcm();
  auto remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  util::StatusOr<std::unique_ptr<Aead>> aead =
      KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  ASSERT_THAT(aead, IsOk());

  std::string message = "Some data to encrypt.";
  std::string aad = "Some associated data.";
  util::StatusOr<std::string> encrypt_result = (*aead)->Encrypt(message, aad);
  ASSERT_THAT(encrypt_result, IsOk());
  auto ciphertext = absl::string_view(*encrypt_result);

  // Ciphertext has size zero or smaller than 4 bytes.
  EXPECT_THAT(
      (*aead)->Decrypt(/*ciphertext=*/"", aad).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("too short")));
  EXPECT_THAT(
      (*aead)->Decrypt(/*ciphertext=*/"sh", aad).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("too short")));

  // Ciphertext is smaller than the size of the key.
  const int dek_encrypted_key_size = absl::big_endian::Load32(
      reinterpret_cast<const uint8_t*>(ciphertext.data()));
  // We leave only key size and key truncated by one.
  EXPECT_THAT(
      (*aead)
          ->Decrypt(ciphertext.substr(0, 4 + dek_encrypted_key_size - 1), aad)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("invalid")));

  std::string corrupted_ciphertext = *encrypt_result;
  // Corrupt the serialized DEK.
  corrupted_ciphertext[4] = 'a';
  EXPECT_THAT(
      (*aead)->Decrypt(corrupted_ciphertext, aad).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("invalid")));

  // Wrong associated data.
  EXPECT_THAT((*aead)->Decrypt(ciphertext, "wrong aad").status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Authentication failed")));
}

TEST_F(KmsEnvelopeAeadTest, DekMaintainsCorrectKeyFormat) {
  ASSERT_THAT(AeadConfig::Register(), IsOk());

  KeyTemplate dek_template = AeadKeyTemplates::Aes128Gcm();
  auto kms_remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  util::StatusOr<std::unique_ptr<Aead>> aead =
      KmsEnvelopeAead::New(dek_template, std::move(kms_remote_aead));
  ASSERT_THAT(aead, IsOk());

  std::string message = "Some data to encrypt.";
  std::string aad = "Some associated data.";
  util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(message, aad);
  ASSERT_THAT(ciphertext, IsOk());

  // Recover DEK from ciphertext (see
  // https://developers.google.com/tink/wire-format#envelope_encryption).
  auto enc_dek_size = absl::big_endian::Load32(
      reinterpret_cast<const uint8_t*>(ciphertext->data()));
  DummyAead remote_aead = DummyAead(kRemoteAeadName);
  absl::string_view encrypted_dek =
      absl::string_view(*ciphertext)
          .substr(kEncryptedDekPrefixSize, enc_dek_size);
  util::StatusOr<std::string> dek_proto_bytes =
      remote_aead.Decrypt(encrypted_dek,
                          /*associated_data=*/"");
  ASSERT_THAT(dek_proto_bytes, IsOk());

  // Check if we can deserialize a GCM key proto from the decrypted DEK.
  google::crypto::tink::AesGcmKey key;
  EXPECT_TRUE(key.ParseFromString(dek_proto_bytes.value()));
  EXPECT_THAT(key.key_value(), SizeIs(16));
}

TEST_F(KmsEnvelopeAeadTest, MultipleEncryptionsProduceDifferentDeks) {
  ASSERT_THAT(AeadConfig::Register(), IsOk());

  KeyTemplate dek_template = AeadKeyTemplates::Aes128Gcm();
  auto kms_remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  util::StatusOr<std::unique_ptr<Aead>> aead =
      KmsEnvelopeAead::New(dek_template, std::move(kms_remote_aead));
  ASSERT_THAT(aead, IsOk());

  std::string message = "Some data to encrypt.";
  std::string aad = "Some associated data.";

  constexpr int kNumIterations = 2;
  std::vector<google::crypto::tink::AesGcmKey> ciphertexts;
  ciphertexts.reserve(kNumIterations);
  for (int i = 0; i < kNumIterations; i++) {
    util::StatusOr<std::string> ciphertext = (*aead)->Encrypt(message, aad);
    ASSERT_THAT(ciphertext, IsOk());

    auto enc_dek_size = absl::big_endian::Load32(
        reinterpret_cast<const uint8_t*>(ciphertext->data()));
    DummyAead remote_aead = DummyAead(kRemoteAeadName);
    util::StatusOr<std::string> dek_proto_bytes = remote_aead.Decrypt(
        ciphertext->substr(kEncryptedDekPrefixSize, enc_dek_size),
        /*associated_data=*/"");
    ASSERT_THAT(dek_proto_bytes, IsOk());

    google::crypto::tink::AesGcmKey key;
    ASSERT_TRUE(key.ParseFromString(dek_proto_bytes.value()));
    ASSERT_THAT(key.key_value(), SizeIs(16));
    ciphertexts.push_back(key);
  }

  for (int i = 0; i < ciphertexts.size() - 1; i++) {
    for (int j = i + 1; j < ciphertexts.size(); j++) {
      EXPECT_THAT(ciphertexts[i].SerializeAsString(),
                  Not(Eq(ciphertexts[j].SerializeAsString())));
    }
  }
}

class KmsEnvelopeAeadDekTemplatesTest
    : public testing::TestWithParam<KeyTemplate> {
  void SetUp() override { ASSERT_THAT(AeadConfig::Register(), IsOk()); }
};

TEST_P(KmsEnvelopeAeadDekTemplatesTest, EncryptDecrypt) {
  // Use an AES-128-GCM primitive as the remote AEAD.
  util::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm());
  ASSERT_THAT(keyset_handle, IsOk());
  util::StatusOr<std::unique_ptr<Aead>> remote_aead =
      (*keyset_handle)->GetPrimitive<Aead>();

  KeyTemplate dek_template = GetParam();
  util::StatusOr<std::unique_ptr<Aead>> envelope_aead =
      KmsEnvelopeAead::New(dek_template, *std::move(remote_aead));
  ASSERT_THAT(envelope_aead, IsOk());

  std::string plaintext = "plaintext";
  std::string associated_data = "associated_data";
  util::StatusOr<std::string> ciphertext =
      (*envelope_aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  util::StatusOr<std::string> decrypted =
      (*envelope_aead)->Decrypt(ciphertext.value(), associated_data);
  EXPECT_THAT(decrypted, IsOkAndHolds(plaintext));
}

std::vector<KeyTemplate> GetTestTemplates() {
  std::vector<KeyTemplate> templates = {
    AeadKeyTemplates::Aes128Gcm(),
    AeadKeyTemplates::Aes256Gcm(),
    AeadKeyTemplates::Aes128CtrHmacSha256(),
    AeadKeyTemplates::Aes128Eax(),
    AeadKeyTemplates::Aes128GcmNoPrefix()
  };
  if (internal::IsBoringSsl()) {
    templates.push_back(AeadKeyTemplates::XChaCha20Poly1305());
    templates.push_back(AeadKeyTemplates::Aes256GcmSiv());
  }
  return templates;
}

INSTANTIATE_TEST_SUITE_P(
    KmsEnvelopeAeadDekTemplatesTest, KmsEnvelopeAeadDekTemplatesTest,
    testing::ValuesIn(GetTestTemplates()));

}  // namespace
}  // namespace tink
}  // namespace crypto
