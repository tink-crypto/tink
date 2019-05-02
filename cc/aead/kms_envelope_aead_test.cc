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

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/registry.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "tink/util/test_matchers.h"
#include "gtest/gtest.h"


namespace crypto {
namespace tink {
namespace {

using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using crypto::tink::test::DummyAead;
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
  EXPECT_THAT(aead_result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                             HasSubstr("non-null")));
}

TEST(KmsEnvelopeAeadTest, MissingDekKeyManager) {
  Registry::Reset();
  auto dek_template = AeadKeyTemplates::Aes128Eax();
  std::string remote_aead_name = "kms-backed-aead";
  auto remote_aead = absl::make_unique<DummyAead>(remote_aead_name);
  auto aead_result = KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  EXPECT_THAT(aead_result.status(), StatusIs(util::error::NOT_FOUND,
                                             HasSubstr("AesEaxKey")));
}

TEST(KmsEnvelopeAeadTest, WrongDekPrimitive) {
  EXPECT_THAT(AeadConfig::Register(), IsOk());
  auto dek_template = MacKeyTemplates::HmacSha256();
  std::string remote_aead_name = "kms-backed-aead";
  auto remote_aead = absl::make_unique<DummyAead>(remote_aead_name);
  auto aead_result = KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  EXPECT_THAT(aead_result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                             HasSubstr("Wrong Primitive")));
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
  EXPECT_THAT(decrypt_result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                                HasSubstr("too short")));

  // Short ciphertext.
  decrypt_result = aead->Decrypt("sh", aad);
  EXPECT_THAT(decrypt_result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                                HasSubstr("too short")));

  // Truncated ciphertext.
  decrypt_result = aead->Decrypt(ct.substr(2), aad);
  EXPECT_THAT(decrypt_result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                                HasSubstr("invalid")));

  // Corrupted ciphertext.
  auto ct_copy = ct;
  ct_copy[4] = 'a';  // corrupt serialized DEK.
  decrypt_result = aead->Decrypt(ct_copy, aad);
  EXPECT_THAT(decrypt_result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                                HasSubstr("invalid")));

  // Wrong associated data.
  decrypt_result = aead->Decrypt(ct, "wrong aad");
  EXPECT_THAT(decrypt_result.status(),
              StatusIs(util::error::INTERNAL,
                       HasSubstr("Authentication failed")));
}


}  // namespace
}  // namespace tink
}  // namespace crypto
