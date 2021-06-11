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

#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_hybrid_key_templates.h"

#include "absl/strings/string_view.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "proto/common.pb.h"
#include "proto/experimental/pqcrypto/cecpq2_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::Cecpq2AeadHkdfKeyFormat;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

KeyTemplate* NewCecpq2AeadHkdfKeyTemplate(EllipticCurveType curve_type,
                                          HashType hkdf_hash_type,
                                          EcPointFormat ec_point_format,
                                          const KeyTemplate& dem_key_template,
                                          OutputPrefixType prefix_type,
                                          absl::string_view hkdf_salt) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey");
  key_template->set_output_prefix_type(prefix_type);
  google::crypto::tink::Cecpq2AeadHkdfKeyFormat key_format;
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  *(dem_params->mutable_aead_dem()) = dem_key_template;
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  kem_params->set_curve_type(curve_type);
  kem_params->set_hkdf_hash_type(hkdf_hash_type);
  std::string hkdf_salt_str(hkdf_salt.data(), hkdf_salt.size());
  kem_params->set_hkdf_salt(hkdf_salt_str);
  kem_params->set_ec_point_format(ec_point_format);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // anonymous namespace

const KeyTemplate& Cecpq2HybridKeyTemplateX25519HkdfHmacSha256Aes256Gcm() {
  static const KeyTemplate* key_template = NewCecpq2AeadHkdfKeyTemplate(
      EllipticCurveType::CURVE25519, HashType::SHA256,
      EcPointFormat::COMPRESSED, AeadKeyTemplates::Aes256Gcm(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

const KeyTemplate&
Cecpq2HybridKeyTemplateX25519HkdfHmacSha256XChaCha20Poly1305() {
  static const KeyTemplate* key_template = NewCecpq2AeadHkdfKeyTemplate(
      EllipticCurveType::CURVE25519, HashType::SHA256,
      EcPointFormat::COMPRESSED, AeadKeyTemplates::XChaCha20Poly1305(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

const google::crypto::tink::KeyTemplate&
Cecpq2HybridKeyTemplateX25519HkdfHmacSha256DeterministicAesSiv() {
  static const KeyTemplate* key_template = NewCecpq2AeadHkdfKeyTemplate(
      EllipticCurveType::CURVE25519, HashType::SHA256,
      EcPointFormat::COMPRESSED, DeterministicAeadKeyTemplates::Aes256Siv(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
