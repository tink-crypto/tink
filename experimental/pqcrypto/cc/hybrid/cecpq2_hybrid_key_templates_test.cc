// Copyright 2021 Google LLC
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

#include "pqcrypto/cc/hybrid/cecpq2_hybrid_key_templates.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_matchers.h"
#include "pqcrypto/cc/hybrid/cecpq2_aead_hkdf_private_key_manager.h"
#include "pqcrypto/cc/hybrid/cecpq2_hybrid_config.h"
#include "pqcrypto/proto/cecpq2_aead_hkdf.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using google::crypto::tink::KeyTemplate;
using ::testing::Eq;

class Cecpq2HybridKeyTemplatesTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    // Initialize the registry, so that the templates can be tested
    ASSERT_THAT(Cecpq2HybridConfigRegister(), IsOk());
  }
};

TEST_F(Cecpq2HybridKeyTemplatesTest,
       ValidateX25519HkdfHmacSha256Aes256GcmKeyFormat) {
  const KeyTemplate& key_template =
      Cecpq2HybridKeyTemplateX25519HkdfHmacSha256Aes256Gcm();
  google::crypto::tink::Cecpq2AeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST_F(Cecpq2HybridKeyTemplatesTest,
       ValidateX25519HkdfHmacSha256XChaCha20Poly1305KeyFormat) {
  const KeyTemplate& key_template =
      Cecpq2HybridKeyTemplateX25519HkdfHmacSha256XChaCha20Poly1305();
  google::crypto::tink::Cecpq2AeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST_F(Cecpq2HybridKeyTemplatesTest,
       ValidateX25519HkdfHmacSha256DeterministicAesSivKeyFormat) {
  const KeyTemplate& key_template =
      Cecpq2HybridKeyTemplateX25519HkdfHmacSha256DeterministicAesSiv();
  google::crypto::tink::Cecpq2AeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(Cecpq2AeadHkdfPrivateKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST_F(Cecpq2HybridKeyTemplatesTest,
       CheckX25519HkdfHmacSha256Aes256GcmTypeUrl) {
  const KeyTemplate& key_template =
      Cecpq2HybridKeyTemplateX25519HkdfHmacSha256Aes256Gcm();
  EXPECT_THAT(
      key_template.type_url(),
      Eq("type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey"));
  google::crypto::tink::Cecpq2AeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.params().dem_params().aead_dem().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
}

TEST_F(Cecpq2HybridKeyTemplatesTest,
       CheckX25519HkdfHmacSha256XChaCha20Poly1305TypeUrl) {
  const KeyTemplate& key_template =
      Cecpq2HybridKeyTemplateX25519HkdfHmacSha256XChaCha20Poly1305();
  EXPECT_THAT(
      key_template.type_url(),
      Eq("type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey"));
  google::crypto::tink::Cecpq2AeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(
      key_format.params().dem_params().aead_dem().type_url(),
      Eq("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"));
}

TEST_F(Cecpq2HybridKeyTemplatesTest,
       CheckX25519HkdfHmacSha256DeterministicAesSivTypeUrl) {
  const KeyTemplate& key_template =
      Cecpq2HybridKeyTemplateX25519HkdfHmacSha256DeterministicAesSiv();
  EXPECT_THAT(
      key_template.type_url(),
      Eq("type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey"));
  google::crypto::tink::Cecpq2AeadHkdfKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.params().dem_params().aead_dem().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesSivKey"));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
