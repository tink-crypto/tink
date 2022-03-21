// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/signature/signature_key_templates.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/constants.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::EcdsaKeyFormat;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::Ed25519PrivateKey;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;
using google::crypto::tink::RsaSsaPkcs1KeyFormat;
using google::crypto::tink::RsaSsaPkcs1PrivateKey;
using google::crypto::tink::RsaSsaPssKeyFormat;
using google::crypto::tink::RsaSsaPssPrivateKey;

std::unique_ptr<KeyTemplate> NewEcdsaKeyTemplate(
    HashType hash_type, EllipticCurveType curve_type,
    EcdsaSignatureEncoding encoding, OutputPrefixType output_prefix_type) {
  auto key_template = absl::make_unique<KeyTemplate>();
  key_template->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, EcdsaPrivateKey().GetTypeName()));
  key_template->set_output_prefix_type(output_prefix_type);
  EcdsaKeyFormat key_format;
  auto params = key_format.mutable_params();
  params->set_hash_type(hash_type);
  params->set_curve(curve_type);
  params->set_encoding(encoding);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

std::unique_ptr<KeyTemplate> NewEcdsaKeyTemplate(
    HashType hash_type, EllipticCurveType curve_type,
    EcdsaSignatureEncoding encoding) {
  return NewEcdsaKeyTemplate(hash_type, curve_type, encoding,
                             OutputPrefixType::TINK);
}

std::unique_ptr<KeyTemplate> NewRsaSsaPkcs1KeyTemplate(HashType hash_type,
                                                       int modulus_size_in_bits,
                                                       int public_exponent) {
  auto key_template = absl::make_unique<KeyTemplate>();
  key_template->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, RsaSsaPkcs1PrivateKey().GetTypeName()));
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  RsaSsaPkcs1KeyFormat key_format;
  auto params = key_format.mutable_params();
  params->set_hash_type(hash_type);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).value());
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

std::unique_ptr<KeyTemplate> NewRsaSsaPssKeyTemplate(HashType sig_hash,
                                                     HashType mgf1_hash,
                                                     int salt_length,
                                                     int modulus_size_in_bits,
                                                     int public_exponent) {
  auto key_template = absl::make_unique<KeyTemplate>();
  key_template->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, RsaSsaPssPrivateKey().GetTypeName()));
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  RsaSsaPssKeyFormat key_format;
  auto params = key_format.mutable_params();
  params->set_sig_hash(sig_hash);
  params->set_mgf1_hash(mgf1_hash);
  params->set_salt_length(salt_length);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).value());
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // anonymous namespace

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP256() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA256, EllipticCurveType::NIST_P256,
                          EcdsaSignatureEncoding::DER)
          .release();
  return *key_template;
}

// Deprecated, use EcdsaP384Sha384() or EcdsaP384Sha512() instead.
// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP384() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA512, EllipticCurveType::NIST_P384,
                          EcdsaSignatureEncoding::DER)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP384Sha384() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA384, EllipticCurveType::NIST_P384,
                          EcdsaSignatureEncoding::DER)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP384Sha512() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA512, EllipticCurveType::NIST_P384,
                          EcdsaSignatureEncoding::DER)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP521() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA512, EllipticCurveType::NIST_P521,
                          EcdsaSignatureEncoding::DER)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP256Raw() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA256, EllipticCurveType::NIST_P256,
                          EcdsaSignatureEncoding::IEEE_P1363,
                          OutputPrefixType::RAW)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP256Ieee() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA256, EllipticCurveType::NIST_P256,
                          EcdsaSignatureEncoding::IEEE_P1363)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP384Ieee() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA512, EllipticCurveType::NIST_P384,
                          EcdsaSignatureEncoding::IEEE_P1363)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP521Ieee() {
  static const KeyTemplate* key_template =
      NewEcdsaKeyTemplate(HashType::SHA512, EllipticCurveType::NIST_P521,
                          EcdsaSignatureEncoding::IEEE_P1363)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4() {
  static const KeyTemplate* key_template =
      NewRsaSsaPkcs1KeyTemplate(HashType::SHA256, 3072, RSA_F4).release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4() {
  static const KeyTemplate* key_template =
      NewRsaSsaPkcs1KeyTemplate(HashType::SHA512, 4096, RSA_F4).release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4() {
  static const KeyTemplate* key_template =
      NewRsaSsaPssKeyTemplate(HashType::SHA256, HashType::SHA256, 32, 3072,
                              RSA_F4)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4() {
  static const KeyTemplate* key_template =
      NewRsaSsaPssKeyTemplate(HashType::SHA512, HashType::SHA512, 64, 4096,
                              RSA_F4)
          .release();
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::RsaSsaPss4096Sha384Sha384F4() {
  static const KeyTemplate* key_template =
      NewRsaSsaPssKeyTemplate(HashType::SHA384, HashType::SHA384, 48, 4096,
                              RSA_F4)
          .release();
  return *key_template;
}

// static
const google::crypto::tink::KeyTemplate& SignatureKeyTemplates::Ed25519() {
  static KeyTemplate* key_template = new KeyTemplate();
  key_template->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, Ed25519PrivateKey().GetTypeName()));
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  return *key_template;
}

// static
const google::crypto::tink::KeyTemplate&
SignatureKeyTemplates::Ed25519WithRawOutput() {
  static KeyTemplate* key_template = new KeyTemplate();
  key_template->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, Ed25519PrivateKey().GetTypeName()));
  key_template->set_output_prefix_type(OutputPrefixType::RAW);
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
