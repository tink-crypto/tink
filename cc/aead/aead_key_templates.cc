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

#include "tink/aead/aead_key_templates.h"

#include <string>

#include "absl/strings/string_view.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesCtrHmacAeadKeyFormat;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::AesGcmSivKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

namespace {

KeyTemplate* NewAesEaxKeyTemplate(int key_size_in_bytes, int iv_size_in_bytes) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesEaxKey");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  AesEaxKeyFormat key_format;
  key_format.set_key_size(key_size_in_bytes);
  key_format.mutable_params()->set_iv_size(iv_size_in_bytes);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewAesGcmKeyTemplate(int key_size_in_bytes,
                                  OutputPrefixType output_prefix_type) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template->set_output_prefix_type(output_prefix_type);
  AesGcmKeyFormat key_format;
  key_format.set_key_size(key_size_in_bytes);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewAesGcmSivKeyTemplate(int key_size_in_bytes) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesGcmSivKey");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  AesGcmSivKeyFormat key_format;
  key_format.set_key_size(key_size_in_bytes);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewAesCtrHmacAeadKeyTemplate(int aes_key_size_in_bytes,
                                          int iv_size_in_bytes,
                                          int hmac_key_size_in_bytes,
                                          int tag_size_in_bytes,
                                          HashType hash_type) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  AesCtrHmacAeadKeyFormat key_format;
  auto aes_ctr_key_format = key_format.mutable_aes_ctr_key_format();
  aes_ctr_key_format->set_key_size(aes_key_size_in_bytes);
  aes_ctr_key_format->mutable_params()->set_iv_size(iv_size_in_bytes);
  auto hmac_key_format = key_format.mutable_hmac_key_format();
  hmac_key_format->set_key_size(hmac_key_size_in_bytes);
  hmac_key_format->mutable_params()->set_hash(hash_type);
  hmac_key_format->mutable_params()->set_tag_size(tag_size_in_bytes);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewXChaCha20Poly1305KeyTemplate() {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  return key_template;
}

}  // anonymous namespace

// static
const KeyTemplate& AeadKeyTemplates::Aes128Eax() {
  static const KeyTemplate* key_template =
      NewAesEaxKeyTemplate(/* key_size_in_bytes= */ 16,
                           /* iv_size_in_bytes= */ 16);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes256Eax() {
  static const KeyTemplate* key_template =
      NewAesEaxKeyTemplate(/* key_size_in_bytes= */ 32,
                           /* iv_size_in_bytes= */ 16);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes128Gcm() {
  static const KeyTemplate* key_template =
      NewAesGcmKeyTemplate(/* key_size_in_bytes= */ 16, OutputPrefixType::TINK);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes128GcmNoPrefix() {
  static const KeyTemplate* key_template =
      NewAesGcmKeyTemplate(/* key_size_in_bytes= */ 16, OutputPrefixType::RAW);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes256Gcm() {
  static const KeyTemplate* key_template =
      NewAesGcmKeyTemplate(/* key_size_in_bytes= */ 32, OutputPrefixType::TINK);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes256GcmNoPrefix() {
  static const KeyTemplate* key_template =
      NewAesGcmKeyTemplate(/* key_size_in_bytes= */ 32, OutputPrefixType::RAW);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes128GcmSiv() {
  static const KeyTemplate* key_template =
      NewAesGcmSivKeyTemplate(/* key_size_in_bytes= */ 16);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes256GcmSiv() {
  static const KeyTemplate* key_template =
      NewAesGcmSivKeyTemplate(/* key_size_in_bytes= */ 32);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes128CtrHmacSha256() {
  static const KeyTemplate* key_template = NewAesCtrHmacAeadKeyTemplate(
      /* aes_key_size_in_bytes= */ 16,
      /* iv_size_in_bytes= */ 16,
      /* hmac_key_size_in_bytes= */ 32,
      /* tag_size_in_bytes= */ 16, HashType::SHA256);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes256CtrHmacSha256() {
  static const KeyTemplate* key_template = NewAesCtrHmacAeadKeyTemplate(
      /* aes_key_size_in_bytes= */ 32,
      /* iv_size_in_bytes= */ 16,
      /* hmac_key_size_in_bytes= */ 32,
      /* tag_size_in_bytes= */ 32, HashType::SHA256);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::XChaCha20Poly1305() {
  static const KeyTemplate* key_template = NewXChaCha20Poly1305KeyTemplate();
  return *key_template;
}

// static
KeyTemplate AeadKeyTemplates::KmsEnvelopeAead(absl::string_view kek_uri,
                                              const KeyTemplate& dek_template) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri(std::string(kek_uri));
  key_format.mutable_dek_template()->MergeFrom(dek_template);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

}  // namespace tink
}  // namespace crypto
