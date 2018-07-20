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

#include "tink/signature/signature_key_templates.h"

#include "tink/signature/ecdsa_sign_key_manager.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::EcdsaKeyFormat;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

TEST(SignatureKeyTemplatesTest, testAesGcmKeyTemplates) {
  std::string type_url = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

  {  // Test EcdsaP256().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP256();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA256, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P256, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::DER, key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = SignatureKeyTemplates::EcdsaP256();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the key manager works with the template.
    EcdsaSignKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result = key_manager.get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test EcdsaP384().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP384();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA512, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P384, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::DER, key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = SignatureKeyTemplates::EcdsaP384();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    EcdsaSignKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result = key_manager.get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test EcdsaP521().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP521();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA512, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P521, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::DER, key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = SignatureKeyTemplates::EcdsaP521();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    EcdsaSignKeyManager key_manager;
    EXPECT_EQ(key_manager.get_key_type(), key_template.type_url());
    auto new_key_result = key_manager.get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto

int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
