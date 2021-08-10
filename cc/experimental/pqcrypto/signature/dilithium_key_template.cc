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

#include "tink/experimental/pqcrypto/signature/dilithium_key_template.h"

#include "tink/util/constants.h"
#include "proto/experimental/pqcrypto/dilithium.pb.h"
#include "proto/experimental/pqcrypto/dilithium.proto.h"
#include "proto/tink.pb.h"
#include "proto/tink.proto.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::DilithiumPrivateKey;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

KeyTemplate* NewDilithiumKeyTemplate() {
  KeyTemplate* key_template = new KeyTemplate;
  key_template->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, DilithiumPrivateKey().GetTypeName()));
  key_template->set_output_prefix_type(OutputPrefixType::TINK);
  return key_template;
}

}  // anonymous namespace

const google::crypto::tink::KeyTemplate& DilithiumKeyTemplate() {
  static const KeyTemplate* key_template = NewDilithiumKeyTemplate();
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
