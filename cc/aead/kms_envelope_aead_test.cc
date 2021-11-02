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

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/base/internal/endian.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"

namespace crypto {
namespace tink {
namespace {

using crypto::tink::test::DummyAead;
using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using testing::HasSubstr;


TEST(KmsEnvelopeAeadTest, BasicEncryptDecrypt) {
  EXPECT_THAT(AeadConfig::Register(), IsOk());

  auto dek_template = AeadKeyTemplates::Aes128Eax();
  std::string remote_aead_name = "kms-backed-aead";
  auto remote_aead = absl::make_unique<DummyAead>(remote_aead_name);

  auto aead_result = KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  EXPECT_THAT(aead_result.status(), IsOk());
  auto aead = std::move(aead_result.ValueOrDie());
  std::string message = "Some data to encrypt.";
  std::string aad = "Some data to authenticate.";
  auto encrypt_result = aead->Encrypt(message, aad);
  EXPECT_THAT(encrypt_result.status(), IsOk());
  auto decrypt_result = aead->Decrypt(encrypt_result.ValueOrDie(), aad);
  EXPECT_THAT(decrypt_result.status(), IsOk());
  EXPECT_EQ(decrypt_result.ValueOrDie(), message);
}

TEST(KmsEnvelopeAeadTest, NullAead) {
  auto dek_template = AeadKeyTemplates::Aes128Eax();
  auto aead_result = KmsEnvelopeAead::New(dek_template, nullptr);
  EXPECT_THAT(aead_result.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                             HasSubstr("non-null")));
}

TEST(KmsEnvelopeAeadTest, MissingDekKeyManager) {
  Registry::Reset();
  auto dek_template = AeadKeyTemplates::Aes128Eax();
  std::string remote_aead_name = "kms-backed-aead";
  auto remote_aead = absl::make_unique<DummyAead>(remote_aead_name);
  auto aead_result = KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  EXPECT_THAT(aead_result.status(),
              StatusIs(absl::StatusCode::kNotFound, HasSubstr("AesEaxKey")));
}

TEST(KmsEnvelopeAeadTest, WrongDekPrimitive) {
  EXPECT_THAT(AeadConfig::Register(), IsOk());
  auto dek_template = MacKeyTemplates::HmacSha256();
  std::string remote_aead_name = "kms-backed-aead";
  auto remote_aead = absl::make_unique<DummyAead>(remote_aead_name);
  auto aead_result = KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  EXPECT_THAT(aead_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("not among supported primitives")));
}

TEST(KmsEnvelopeAeadTest, DecryptionErrors) {
  EXPECT_THAT(AeadConfig::Register(), IsOk());

  auto dek_template = AeadKeyTemplates::Aes128Gcm();
  std::string remote_aead_name = "kms-backed-aead";
  auto remote_aead = absl::make_unique<DummyAead>(remote_aead_name);

  auto aead_result = KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  EXPECT_THAT(aead_result.status(), IsOk());
  auto aead = std::move(aead_result.ValueOrDie());
  std::string message = "Some data to encrypt.";
  std::string aad = "Some data to authenticate.";
  auto encrypt_result = aead->Encrypt(message, aad);
  EXPECT_THAT(encrypt_result.status(), IsOk());
  auto ct = encrypt_result.ValueOrDie();

  // Empty ciphertext.
  auto decrypt_result = aead->Decrypt("", aad);
  EXPECT_THAT(
      decrypt_result.status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("too short")));

  // Short ciphertext.
  decrypt_result = aead->Decrypt("sh", aad);
  EXPECT_THAT(
      decrypt_result.status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("too short")));

  // Truncated ciphertext.
  decrypt_result = aead->Decrypt(ct.substr(2), aad);
  EXPECT_THAT(
      decrypt_result.status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("invalid")));

  // Corrupted ciphertext.
  auto ct_copy = ct;
  ct_copy[4] = 'a';  // corrupt serialized DEK.
  decrypt_result = aead->Decrypt(ct_copy, aad);
  EXPECT_THAT(
      decrypt_result.status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("invalid")));

  // Wrong associated data.
  decrypt_result = aead->Decrypt(ct, "wrong aad");
  EXPECT_THAT(decrypt_result.status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Authentication failed")));
}

TEST(KmsEnvelopeAeadTest, KeyFormat) {
  EXPECT_THAT(AeadConfig::Register(), IsOk());

  auto dek_template = AeadKeyTemplates::Aes128Gcm();

  // Construct a remote AEAD which uses same key template for this test.
  std::string remote_aead_name = "kms-backed-aead";
  auto remote_aead = absl::make_unique<DummyAead>(remote_aead_name);

  // Create envelope AEAD and encrypt some data.
  auto aead_result = KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  EXPECT_THAT(aead_result.status(), IsOk());

  auto aead = std::move(aead_result.ValueOrDie());
  std::string message = "Some data to encrypt.";
  std::string aad = "Some data to authenticate.";
  auto encrypt_result = aead->Encrypt(message, aad);
  EXPECT_THAT(encrypt_result.status(), IsOk());
  auto ct = encrypt_result.ValueOrDie();

  // Recover DEK from ciphertext
  auto enc_dek_size =
      absl::big_endian::Load32(reinterpret_cast<const uint8_t*>(ct.data()));

  remote_aead = absl::make_unique<DummyAead>(remote_aead_name);
  auto dek_decrypt_result =
      remote_aead->Decrypt(ct.substr(4, enc_dek_size), "");

  // Check if we can deserialize a GCM key proto from the decrypted DEK.
  google::crypto::tink::AesGcmKey key;
  EXPECT_THAT(key.ParseFromString(dek_decrypt_result.ValueOrDie()), true);
  EXPECT_THAT(key.key_value().size(), testing::Eq(16));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
