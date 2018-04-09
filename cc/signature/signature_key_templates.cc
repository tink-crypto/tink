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

#include "proto/ecdsa.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::EcdsaKeyFormat;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

KeyTemplate* NewEcdsaKeyTemplate(HashType hash_type,
                                 EllipticCurveType curve_type,
                                 EcdsaSignatureEncoding encoding) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  EcdsaKeyFormat key_format;
  auto params = key_format.mutable_params();
  params->set_hash_type(hash_type);
  params->set_curve(curve_type);
  params->set_encoding(encoding);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // anonymous namespace

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP256() {
  static const KeyTemplate* key_template = NewEcdsaKeyTemplate(
      HashType::SHA256,
      EllipticCurveType::NIST_P256,
      EcdsaSignatureEncoding::DER);
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP384() {
  static const KeyTemplate* key_template = NewEcdsaKeyTemplate(
      HashType::SHA512,
      EllipticCurveType::NIST_P384,
      EcdsaSignatureEncoding::DER);
  return *key_template;
}

// static
const KeyTemplate& SignatureKeyTemplates::EcdsaP521() {
  static const KeyTemplate* key_template = NewEcdsaKeyTemplate(
      HashType::SHA512,
      EllipticCurveType::NIST_P521,
      EcdsaSignatureEncoding::DER);
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
