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

#include "tink/daead/deterministic_aead_key_templates.h"

#include "proto/aes_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesSivKeyFormat;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

namespace {

KeyTemplate* NewAesSivKeyTemplate(int key_size_in_bytes) {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesSivKey");
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  AesSivKeyFormat key_format;
  key_format.set_key_size(key_size_in_bytes);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // anonymous namespace

// static
const KeyTemplate& DeterministicAeadKeyTemplates::Aes256Siv() {
  static const KeyTemplate* key_template =
      NewAesSivKeyTemplate(/* key_size_in_bytes= */ 64);
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
