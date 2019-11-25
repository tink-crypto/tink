// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
#include "tink/prf/prf_key_templates.h"

#include "tink/prf/hkdf_prf_key_manager.h"
#include "proto/hkdf_prf.pb.h"

namespace crypto {
namespace tink {

namespace {

using google::crypto::tink::HkdfPrfKeyFormat;

std::unique_ptr<google::crypto::tink::KeyTemplate> NewHkdfSha256Template() {
  auto key_template = absl::make_unique<google::crypto::tink::KeyTemplate>();
  key_template->set_type_url(HkdfPrfKeyManager().get_key_type());
  key_template->set_output_prefix_type(
      google::crypto::tink::OutputPrefixType::TINK);
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_hash(google::crypto::tink::HashType::SHA256);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // namespace

const google::crypto::tink::KeyTemplate& PrfKeyTemplates::HkdfSha256() {
  static const google::crypto::tink::KeyTemplate* key_template =
      NewHkdfSha256Template().release();
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
