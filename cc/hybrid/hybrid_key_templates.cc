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

#include "tink/hybrid/hybrid_key_templates.h"

#include "absl/strings/string_view.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::EciesAeadHkdfKeyFormat;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::HpkeAead;
using google::crypto::tink::HpkeKdf;
using google::crypto::tink::HpkeKem;
using google::crypto::tink::HpkeKeyFormat;
using google::crypto::tink::HpkeParams;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

KeyTemplate* NewEciesAeadHkdfKeyTemplate(
    EllipticCurveType curve_type,
    HashType hkdf_hash_type,
    EcPointFormat ec_point_format,
    const KeyTemplate& dem_key_template,
    OutputPrefixType prefix_type,
    absl::string_view hkdf_salt) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey");
  key_template->set_output_prefix_type(prefix_type);
  EciesAeadHkdfKeyFormat key_format;
  key_format.mutable_params()->set_ec_point_format(ec_point_format);
  auto dem_params = key_format.mutable_params()->mutable_dem_params();
  *(dem_params->mutable_aead_dem()) = dem_key_template;
  auto kem_params = key_format.mutable_params()->mutable_kem_params();
  kem_params->set_curve_type(curve_type);
  kem_params->set_hkdf_hash_type(hkdf_hash_type);
  kem_params->set_hkdf_salt(std::string(hkdf_salt));
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewHpkeKeyTemplate(HpkeKem kem, HpkeKdf kdf, HpkeAead aead,
                                OutputPrefixType prefix_type) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey");
  key_template->set_output_prefix_type(prefix_type);
  HpkeKeyFormat key_format;
  HpkeParams* params = key_format.mutable_params();
  params->set_kem(kem);
  params->set_kdf(kdf);
  params->set_aead(aead);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // anonymous namespace

// static
const KeyTemplate& HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm() {
  static const KeyTemplate* key_template =
      NewEciesAeadHkdfKeyTemplate(EllipticCurveType::NIST_P256,
                                  HashType::SHA256,
                                  EcPointFormat::UNCOMPRESSED,
                                  AeadKeyTemplates::Aes128Gcm(),
                                  OutputPrefixType::TINK,
                                  /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate& HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128Gcm() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::NIST_P256, HashType::SHA512,
      EcPointFormat::UNCOMPRESSED, AeadKeyTemplates::Aes128Gcm(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128GcmCompressedWithoutPrefix() {
  static const KeyTemplate* key_template =
      NewEciesAeadHkdfKeyTemplate(EllipticCurveType::NIST_P256,
                                  HashType::SHA256,
                                  EcPointFormat::COMPRESSED,
                                  AeadKeyTemplates::Aes128Gcm(),
                                  OutputPrefixType::RAW,
                                  /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128CtrHmacSha256() {
  static const KeyTemplate* key_template =
      NewEciesAeadHkdfKeyTemplate(EllipticCurveType::NIST_P256,
                                  HashType::SHA256,
                                  EcPointFormat::UNCOMPRESSED,
                                  AeadKeyTemplates::Aes128CtrHmacSha256(),
                                  OutputPrefixType::TINK,
                                  /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::EciesP256HkdfHmacSha512Aes128CtrHmacSha256() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::NIST_P256, HashType::SHA512,
      EcPointFormat::UNCOMPRESSED, AeadKeyTemplates::Aes128CtrHmacSha256(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128Gcm() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::NIST_P256, HashType::SHA256, EcPointFormat::COMPRESSED,
      AeadKeyTemplates::Aes128Gcm(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::EciesP256CompressedHkdfHmacSha256Aes128CtrHmacSha256() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::NIST_P256, HashType::SHA256, EcPointFormat::COMPRESSED,
      AeadKeyTemplates::Aes128CtrHmacSha256(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate& HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128Gcm() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::CURVE25519, HashType::SHA256,
      EcPointFormat::COMPRESSED, AeadKeyTemplates::Aes128Gcm(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate& HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes256Gcm() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::CURVE25519, HashType::SHA256,
      EcPointFormat::COMPRESSED, AeadKeyTemplates::Aes256Gcm(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes128CtrHmacSha256() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::CURVE25519, HashType::SHA256,
      EcPointFormat::COMPRESSED, AeadKeyTemplates::Aes128CtrHmacSha256(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::EciesX25519HkdfHmacSha256XChaCha20Poly1305() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::CURVE25519, HashType::SHA256,
      EcPointFormat::COMPRESSED, AeadKeyTemplates::XChaCha20Poly1305(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::EciesX25519HkdfHmacSha256DeterministicAesSiv() {
  static const KeyTemplate* key_template = NewEciesAeadHkdfKeyTemplate(
      EllipticCurveType::CURVE25519, HashType::SHA256,
      EcPointFormat::COMPRESSED, DeterministicAeadKeyTemplates::Aes256Siv(),
      OutputPrefixType::TINK,
      /* hkdf_salt= */ "");
  return *key_template;
}

// static
const KeyTemplate& HybridKeyTemplates::HpkeX25519HkdfSha256Aes128Gcm() {
  static const KeyTemplate* key_template = NewHpkeKeyTemplate(
      HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
      HpkeAead::AES_128_GCM, OutputPrefixType::TINK);
  return *key_template;
}

// static
const KeyTemplate& HybridKeyTemplates::HpkeX25519HkdfSha256Aes256Gcm() {
  static const KeyTemplate* key_template = NewHpkeKeyTemplate(
      HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
      HpkeAead::AES_256_GCM, OutputPrefixType::TINK);
  return *key_template;
}

// static
const KeyTemplate&
HybridKeyTemplates::HpkeX25519HkdfSha256ChaCha20Poly1305() {
  static const KeyTemplate* key_template = NewHpkeKeyTemplate(
      HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
      HpkeAead::CHACHA20_POLY1305, OutputPrefixType::TINK);
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
