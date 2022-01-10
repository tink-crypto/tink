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

#include <string>

#include "gtest/gtest.h"
#include "openssl/base.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/private_key_manager_impl.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_sign_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using google::crypto::tink::EcdsaKeyFormat;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::Ed25519KeyFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;
using google::crypto::tink::RsaSsaPkcs1KeyFormat;
using google::crypto::tink::RsaSsaPssKeyFormat;

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithDerEncoding) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

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
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);

    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test EcdsaP256Raw().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP256Raw();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::RAW, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA256, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P256, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::IEEE_P1363,
              key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = SignatureKeyTemplates::EcdsaP256Raw();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the key manager works with the template.
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);

    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
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
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test EcdsaP384Sha512().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP384Sha512();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA512, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P384, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::DER, key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template2 = SignatureKeyTemplates::EcdsaP384Sha512();
    EXPECT_EQ(&key_template, &key_template2);

    // Check that the template works with the key manager.
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test EcdsaP384Sha384().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP384Sha384();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA384, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P384, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::DER, key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template2 = SignatureKeyTemplates::EcdsaP384Sha384();
    EXPECT_EQ(&key_template, &key_template2);

    // Check that the template works with the key manager.
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
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
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithIeeeEncoding) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

  {  // Test EcdsaP256Ieee().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP256Ieee();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA256, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P256, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::IEEE_P1363,
              key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = SignatureKeyTemplates::EcdsaP256Ieee();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the key manager works with the template.
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test EcdsaP384Ieee().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP384Ieee();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA512, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P384, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::IEEE_P1363,
              key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = SignatureKeyTemplates::EcdsaP384Ieee();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }

  {  // Test EcdsaP521Ieee().
    // Check that returned template is correct.
    const KeyTemplate& key_template = SignatureKeyTemplates::EcdsaP521Ieee();
    EXPECT_EQ(type_url, key_template.type_url());
    EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
    EcdsaKeyFormat key_format;
    EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
    EXPECT_EQ(HashType::SHA512, key_format.params().hash_type());
    EXPECT_EQ(EllipticCurveType::NIST_P521, key_format.params().curve());
    EXPECT_EQ(EcdsaSignatureEncoding::IEEE_P1363,
              key_format.params().encoding());

    // Check that reference to the same object is returned.
    const KeyTemplate& key_template_2 = SignatureKeyTemplates::EcdsaP521Ieee();
    EXPECT_EQ(&key_template, &key_template_2);

    // Check that the template works with the key manager.
    EcdsaSignKeyManager sign_key_type_manager;
    EcdsaVerifyKeyManager verify_key_type_manager;
    auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
        &sign_key_type_manager, &verify_key_type_manager);
    EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
    auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
    EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
  }
}

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithRsaSsaPkcs13072Sha256F4) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";

  const KeyTemplate& key_template =
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  RsaSsaPkcs1KeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(HashType::SHA256, key_format.params().hash_type());
  EXPECT_GE(key_format.modulus_size_in_bits(), 3072);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> resulting_bn =
      internal::StringToBignum(key_format.public_exponent());
  ASSERT_THAT(resulting_bn.status(), IsOk());
  EXPECT_EQ(BN_cmp(resulting_bn->get(), e.get()), 0);
  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the key manager works with the template.
  RsaSsaPkcs1SignKeyManager key_type_manager;
  auto key_manager = internal::MakeKeyManager<PublicKeySign>(&key_type_manager);
  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithRsaSsaPkcs14096Sha512F4) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  const KeyTemplate& key_template =
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  RsaSsaPkcs1KeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(HashType::SHA512, key_format.params().hash_type());
  EXPECT_GE(key_format.modulus_size_in_bits(), 4096);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> resulting_bn =
      internal::StringToBignum(key_format.public_exponent());
  ASSERT_THAT(resulting_bn.status(), IsOk());
  EXPECT_EQ(BN_cmp(resulting_bn->get(), e.get()), 0);
  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the key manager works with the template.
  RsaSsaPkcs1SignKeyManager key_type_manager;
  auto key_manager = internal::MakeKeyManager<PublicKeySign>(&key_type_manager);
  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithRsaSsaPss3072Sha256Sha256F4) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  const KeyTemplate& key_template =
      SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  RsaSsaPssKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(HashType::SHA256, key_format.params().sig_hash());
  EXPECT_EQ(HashType::SHA256, key_format.params().mgf1_hash());
  EXPECT_EQ(32, key_format.params().salt_length());
  EXPECT_GE(key_format.modulus_size_in_bits(), 3072);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> resulting_bn =
      internal::StringToBignum(key_format.public_exponent());
  ASSERT_THAT(resulting_bn.status(), IsOk());
  EXPECT_EQ(BN_cmp(resulting_bn->get(), e.get()), 0);

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the key manager works with the template.
  RsaSsaPssSignKeyManager key_type_manager;
  auto key_manager = internal::MakeKeyManager<PublicKeySign>(&key_type_manager);
  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithRsaSsaPss4096Sha384Sha384F4) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  const KeyTemplate& key_template =
      SignatureKeyTemplates::RsaSsaPss4096Sha384Sha384F4();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  RsaSsaPssKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(HashType::SHA384, key_format.params().sig_hash());
  EXPECT_EQ(HashType::SHA384, key_format.params().mgf1_hash());
  EXPECT_EQ(48, key_format.params().salt_length());
  EXPECT_GE(key_format.modulus_size_in_bits(), 4096);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> resulting_bn =
      internal::StringToBignum(key_format.public_exponent());
  ASSERT_THAT(resulting_bn.status(), IsOk());
  EXPECT_EQ(BN_cmp(resulting_bn->get(), e.get()), 0);

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      SignatureKeyTemplates::RsaSsaPss4096Sha384Sha384F4();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the key manager works with the template.
  RsaSsaPssSignKeyManager key_type_manager;
  auto key_manager = internal::MakeKeyManager<PublicKeySign>(&key_type_manager);
  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithRsaSsaPss4096Sha512Sha512F4) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
  const KeyTemplate& key_template =
      SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
  RsaSsaPssKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_EQ(HashType::SHA512, key_format.params().sig_hash());
  EXPECT_EQ(HashType::SHA512, key_format.params().mgf1_hash());
  EXPECT_EQ(64, key_format.params().salt_length());
  EXPECT_GE(key_format.modulus_size_in_bits(), 4096);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);

  util::StatusOr<internal::SslUniquePtr<BIGNUM>> resulting_bn =
      internal::StringToBignum(key_format.public_exponent());
  ASSERT_THAT(resulting_bn.status(), IsOk());
  EXPECT_EQ(BN_cmp(resulting_bn->get(), e.get()), 0);

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the key manager works with the template.
  RsaSsaPssSignKeyManager key_type_manager;
  auto key_manager = internal::MakeKeyManager<PublicKeySign>(&key_type_manager);
  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithEd25519) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
  const KeyTemplate& key_template = SignatureKeyTemplates::Ed25519();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 = SignatureKeyTemplates::Ed25519();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the key manager works with the template.
  Ed25519SignKeyManager sign_key_type_manager;
  Ed25519VerifyKeyManager verify_key_type_manager;
  auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
      &sign_key_type_manager, &verify_key_type_manager);

  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  Ed25519KeyFormat key_format;
  auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

TEST(SignatureKeyTemplatesTest, KeyTemplatesWithEd25519WithRawOutput) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";
  const KeyTemplate& key_template =
      SignatureKeyTemplates::Ed25519WithRawOutput();
  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::RAW, key_template.output_prefix_type());

  // Check that reference to the same object is returned.
  const KeyTemplate& key_template_2 =
      SignatureKeyTemplates::Ed25519WithRawOutput();
  EXPECT_EQ(&key_template, &key_template_2);

  // Check that the key manager works with the template.
  Ed25519SignKeyManager sign_key_type_manager;
  Ed25519VerifyKeyManager verify_key_type_manager;
  auto key_manager = internal::MakePrivateKeyManager<PublicKeySign>(
      &sign_key_type_manager, &verify_key_type_manager);

  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());
  Ed25519KeyFormat key_format;
  auto new_key_result = key_manager->get_key_factory().NewKey(key_format);
  EXPECT_TRUE(new_key_result.ok()) << new_key_result.status();
}

}  // namespace
}  // namespace tink
}  // namespace crypto
