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

#include "tink/mac/mac_key_templates.h"

#include "proto/aes_cmac.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::AesCmacKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::HmacKeyFormat;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

KeyTemplate* NewHmacKeyTemplate(int key_size_in_bytes, int tag_size_in_bytes,
                                HashType hash_type) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url("type.googleapis.com/google.crypto.tink.HmacKey");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  HmacKeyFormat key_format;
  key_format.set_key_size(key_size_in_bytes);
  key_format.mutable_params()->set_tag_size(tag_size_in_bytes);
  key_format.mutable_params()->set_hash(hash_type);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

KeyTemplate* NewAesCmacKeyTemplate(int key_size_in_bytes,
                                   int tag_size_in_bytes) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesCmacKey");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  AesCmacKeyFormat key_format;
  key_format.set_key_size(key_size_in_bytes);
  key_format.mutable_params()->set_tag_size(tag_size_in_bytes);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // anonymous namespace

// static
const KeyTemplate& MacKeyTemplates::HmacSha256HalfSizeTag() {
  static const KeyTemplate* key_template =
      NewHmacKeyTemplate(/* key_size_in_bytes= */ 32,
                         /* tag_size_in_bytes= */ 16, HashType::SHA256);
  return *key_template;
}

// static
const KeyTemplate& MacKeyTemplates::HmacSha256() {
  static const KeyTemplate* key_template =
      NewHmacKeyTemplate(/* key_size_in_bytes= */ 32,
                         /* tag_size_in_bytes= */ 32, HashType::SHA256);
  return *key_template;
}

// static
const KeyTemplate& MacKeyTemplates::HmacSha512HalfSizeTag() {
  static const KeyTemplate* key_template =
      NewHmacKeyTemplate(/* key_size_in_bytes= */ 64,
                         /* tag_size_in_bytes= */ 32, HashType::SHA512);
  return *key_template;
}

// static
const KeyTemplate& MacKeyTemplates::HmacSha512() {
  static const KeyTemplate* key_template =
      NewHmacKeyTemplate(/* key_size_in_bytes= */ 64,
                         /* tag_size_in_bytes= */ 64, HashType::SHA512);
  return *key_template;
}

// static
const KeyTemplate& MacKeyTemplates::AesCmac() {
  static const KeyTemplate* key_template = NewAesCmacKeyTemplate(
      /* key_size_in_bytes= */ 32, /* tag_size_in_bytes= */ 16);
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
