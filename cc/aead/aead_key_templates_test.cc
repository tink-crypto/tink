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

#include "tink/aead/aead_key_templates.h"

#include "gtest/gtest.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

using google::crypto::tink::AesCtrHmacAeadKeyFormat;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

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
    AesEaxKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager.get_key_factory().NewKey(key_template.value());
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
    AesEaxKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager.get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

TEST(AeadKeyTemplatesTest, testAesGcmKeyTemplates) {
  std::string type_url = "type.googleapis.com/google.crypto.tink.AesGcmKey";

  {  // Test Aes128Gcm().
    // Check that returned template is correct.
    const KeyTemplate& key_template = AeadKeyTemplates::Aes128Gcm();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesGcmKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(16, key_format.key_size());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = AeadKeyTemplates::Aes128Gcm();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesGcmKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager.get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test Aes256Gcm().
    // Check that returned template is correct.
    const KeyTemplate& key_template = AeadKeyTemplates::Aes256Gcm();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    AesGcmKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(32, key_format.key_size());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = AeadKeyTemplates::Aes256Gcm();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    AesGcmKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager.get_key_factory().NewKey(key_template.value());
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

TEST(AeadKeyTemplatesTest, testAesCtrHmacAeadKeyTemplates) {
  std::string type_url = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

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
    AesCtrHmacAeadKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager.get_key_factory().NewKey(key_template.value());
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
    AesCtrHmacAeadKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result =
        key_manager.get_key_factory().NewKey(key_template.value());
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
  XChaCha20Poly1305KeyManager key_manager;
  EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
  auto new_key_result =
      key_manager.get_key_factory().NewKey(key_template.value());
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

}  // namespace
}  // namespace tink
}  // namespace crypto
