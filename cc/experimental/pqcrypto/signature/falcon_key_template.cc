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

#include "tink/experimental/pqcrypto/signature/falcon_key_template.h"

#include <memory>

#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/util/constants.h"
#include "proto/experimental/pqcrypto/falcon.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using google::crypto::tink::FalconKeyFormat;
using google::crypto::tink::FalconPrivateKey;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

std::unique_ptr<KeyTemplate> NewFalconKeyTemplate(int32_t key_size) {
  auto key_template = absl::make_unique<KeyTemplate>();
  key_template->set_type_url(
      absl::StrCat(kTypeGoogleapisCom, FalconPrivateKey().GetTypeName()));
  key_template->set_output_prefix_type(OutputPrefixType::TINK);

  FalconKeyFormat key_format;
  key_format.set_key_size(key_size);
  key_format.SerializeToString(key_template->mutable_value());

  return key_template;
}

}  // anonymous namespace

const google::crypto::tink::KeyTemplate& Falcon512KeyTemplate() {
  static const KeyTemplate* key_template =
      NewFalconKeyTemplate(subtle::kFalcon512PrivateKeySize).release();
  return *key_template;
}

const google::crypto::tink::KeyTemplate& Falcon1024KeyTemplate() {
  static const KeyTemplate* key_template =
      NewFalconKeyTemplate(subtle::kFalcon1024PrivateKeySize).release();
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
