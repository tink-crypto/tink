// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/streaming_aead_key_templates.h"

#include "proto/aes_ctr_hmac_streaming.pb.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesCtrHmacStreamingKeyFormat;
using google::crypto::tink::AesGcmHkdfStreamingKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

namespace {

KeyTemplate* NewAesGcmHkdfStreamingKeyTemplate(int ikm_size_in_bytes,
                                               int segment_size_in_bytes) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey");
  key_template->set_output_prefix_type(OutputPrefixType::RAW);
  AesGcmHkdfStreamingKeyFormat key_format;
  key_format.set_key_size(ikm_size_in_bytes);
  auto params = key_format.mutable_params();
  params->set_ciphertext_segment_size(segment_size_in_bytes);
  params->set_derived_key_size(ikm_size_in_bytes);
  params->set_hkdf_hash_type(HashType::SHA256);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewAesCtrHmacStreamingKeyTemplate(int ikm_size_in_bytes) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey");
  key_template->set_output_prefix_type(OutputPrefixType::RAW);
  AesCtrHmacStreamingKeyFormat key_format;
  key_format.set_key_size(ikm_size_in_bytes);
  auto params = key_format.mutable_params();
  params->set_ciphertext_segment_size(4096);
  params->set_derived_key_size(ikm_size_in_bytes);
  params->set_hkdf_hash_type(HashType::SHA256);
  auto hmac_params = params->mutable_hmac_params();
  hmac_params->set_hash(HashType::SHA256);
  hmac_params->set_tag_size(32);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // anonymous namespace

// static
const KeyTemplate& StreamingAeadKeyTemplates::Aes128GcmHkdf4KB() {
  static const KeyTemplate* key_template = NewAesGcmHkdfStreamingKeyTemplate(
      /* ikm_size_in_bytes= */ 16, /* segment_size_in_bytes= */ 4096);
  return *key_template;
}

// static
const KeyTemplate& StreamingAeadKeyTemplates::Aes256GcmHkdf4KB() {
  static const KeyTemplate* key_template = NewAesGcmHkdfStreamingKeyTemplate(
      /* ikm_size_in_bytes= */ 32, /* segment_size_in_bytes= */ 4096);
  return *key_template;
}

// static
const KeyTemplate& StreamingAeadKeyTemplates::Aes256GcmHkdf1MB() {
  static const KeyTemplate* key_template = NewAesGcmHkdfStreamingKeyTemplate(
      /* ikm_size_in_bytes= */ 32, /* segment_size_in_bytes= */ 1048576);
  return *key_template;
}

// static
const KeyTemplate& StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB() {
  static const KeyTemplate* key_template =
      NewAesCtrHmacStreamingKeyTemplate(/* ikm_size_in_bytes= */ 16);
  return *key_template;
}

// static
const KeyTemplate& StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB() {
  static const KeyTemplate* key_template =
      NewAesCtrHmacStreamingKeyTemplate(/* ikm_size_in_bytes= */ 32);
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
