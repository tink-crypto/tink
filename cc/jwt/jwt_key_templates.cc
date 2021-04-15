// Copyright 2021 Google LLC
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

#include "tink/jwt/jwt_key_templates.h"

#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "proto/common.pb.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

using ::google::crypto::tink::HashType;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::JwtHmacKeyFormat;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPssKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

namespace {

KeyTemplate* NewJwtHmacKeyTemplate(HashType hash_type) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtHmacKey");
  key_template->set_output_prefix_type(OutputPrefixType::RAW);
  JwtHmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_hash_type(hash_type);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewJwtEcdsaKeyTemplate(JwtEcdsaAlgorithm algorithm) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey");
  key_template->set_output_prefix_type(OutputPrefixType::RAW);
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(algorithm);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewJwtRsaSsaPkcs1KeyTemplate(JwtRsaSsaPkcs1Algorithm algorithm,
                                          int modulus_size_in_bits,
                                          int public_exponent) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey");
  key_template->set_output_prefix_type(OutputPrefixType::RAW);
  JwtRsaSsaPkcs1KeyFormat key_format;
  key_format.set_algorithm(algorithm);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);
  bssl::UniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      subtle::SubtleUtilBoringSSL::bn2str(e.get(), BN_num_bytes(e.get()))
          .ValueOrDie());
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewJwtRsaSsaPssKeyTemplate(JwtRsaSsaPssAlgorithm algorithm,
                                          int modulus_size_in_bits,
                                          int public_exponent) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey");
  key_template->set_output_prefix_type(OutputPrefixType::RAW);
  JwtRsaSsaPssKeyFormat key_format;
  key_format.set_algorithm(algorithm);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);
  bssl::UniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      subtle::SubtleUtilBoringSSL::bn2str(e.get(), BN_num_bytes(e.get()))
          .ValueOrDie());
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // anonymous namespace

const KeyTemplate& JwtHs256Template() {
  static const KeyTemplate* key_template =
      NewJwtHmacKeyTemplate(HashType::SHA256);
  return *key_template;
}

const KeyTemplate& JwtHs384Template() {
  static const KeyTemplate* key_template =
      NewJwtHmacKeyTemplate(HashType::SHA384);
  return *key_template;
}

const KeyTemplate& JwtHs512Template() {
  static const KeyTemplate* key_template =
      NewJwtHmacKeyTemplate(HashType::SHA512);
  return *key_template;
}

const KeyTemplate& JwtEs256Template() {
  static const KeyTemplate* key_template =
      NewJwtEcdsaKeyTemplate(JwtEcdsaAlgorithm::ES256);
  return *key_template;
}

const KeyTemplate& JwtEs384Template() {
  static const KeyTemplate* key_template =
      NewJwtEcdsaKeyTemplate(JwtEcdsaAlgorithm::ES384);
  return *key_template;
}

const KeyTemplate& JwtEs512Template() {
  static const KeyTemplate* key_template =
      NewJwtEcdsaKeyTemplate(JwtEcdsaAlgorithm::ES512);
  return *key_template;
}

const KeyTemplate& JwtRs256_2048_F4_Template() {
  static const KeyTemplate* key_template = NewJwtRsaSsaPkcs1KeyTemplate(
      JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);
  return *key_template;
}

const KeyTemplate& JwtRs256_3072_F4_Template() {
  static const KeyTemplate* key_template = NewJwtRsaSsaPkcs1KeyTemplate(
      JwtRsaSsaPkcs1Algorithm::RS256, 3072, RSA_F4);
  return *key_template;
}

const KeyTemplate& JwtRs384_3072_F4_Template() {
  static const KeyTemplate* key_template = NewJwtRsaSsaPkcs1KeyTemplate(
      JwtRsaSsaPkcs1Algorithm::RS384, 3072, RSA_F4);
  return *key_template;
}

const KeyTemplate& JwtRs512_4096_F4_Template() {
  static const KeyTemplate* key_template = NewJwtRsaSsaPkcs1KeyTemplate(
      JwtRsaSsaPkcs1Algorithm::RS512, 4096, RSA_F4);
  return *key_template;
}

const KeyTemplate& JwtPs256_2048_F4_Template() {
  static const KeyTemplate* key_template = NewJwtRsaSsaPssKeyTemplate(
      JwtRsaSsaPssAlgorithm::PS256, 2048, RSA_F4);
  return *key_template;
}

const KeyTemplate& JwtPs256_3072_F4_Template() {
  static const KeyTemplate* key_template = NewJwtRsaSsaPssKeyTemplate(
      JwtRsaSsaPssAlgorithm::PS256, 3072, RSA_F4);
  return *key_template;
}

const KeyTemplate& JwtPs384_3072_F4_Template() {
  static const KeyTemplate* key_template = NewJwtRsaSsaPssKeyTemplate(
      JwtRsaSsaPssAlgorithm::PS384, 3072, RSA_F4);
  return *key_template;
}

const KeyTemplate& JwtPs512_4096_F4_Template() {
  static const KeyTemplate* key_template = NewJwtRsaSsaPssKeyTemplate(
      JwtRsaSsaPssAlgorithm::PS512, 4096, RSA_F4);
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
