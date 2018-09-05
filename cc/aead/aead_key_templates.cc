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

KeyTemplate* NewAesGcmKeyTemplate(int key_size_in_bytes) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  AesGcmKeyFormat key_format;
  key_format.set_key_size(key_size_in_bytes);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewAesCtrHmacAeadKeyTemplate(
    int aes_key_size_in_bytes, int iv_size_in_bytes,
    int hmac_key_size_in_bytes, int tag_size_in_bytes,
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
      NewAesGcmKeyTemplate(/* key_size_in_bytes= */ 16);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes256Gcm() {
  static const KeyTemplate* key_template =
      NewAesGcmKeyTemplate(/* key_size_in_bytes= */ 32);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes128CtrHmacSha256() {
  static const KeyTemplate* key_template = NewAesCtrHmacAeadKeyTemplate(
      /* aes_key_size_in_bytes= */ 16,
      /* iv_size_in_bytes= */ 16,
      /* hmac_key_size_in_bytes= */ 32,
      /* tag_size_in_bytes= */ 16,
      HashType::SHA256);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::Aes256CtrHmacSha256() {
  static const KeyTemplate* key_template = NewAesCtrHmacAeadKeyTemplate(
      /* aes_key_size_in_bytes= */ 32,
      /* iv_size_in_bytes= */ 16,
      /* hmac_key_size_in_bytes= */ 32,
      /* tag_size_in_bytes= */ 32,
      HashType::SHA256);
  return *key_template;
}

// static
const KeyTemplate& AeadKeyTemplates::XChaCha20Poly1305() {
  static const KeyTemplate* key_template = NewXChaCha20Poly1305KeyTemplate();
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
