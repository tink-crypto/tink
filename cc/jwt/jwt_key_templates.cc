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

#include "proto/common.pb.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

using ::google::crypto::tink::HashType;
using ::google::crypto::tink::JwtHmacKeyFormat;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
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

}  // namespace tink
}  // namespace crypto
