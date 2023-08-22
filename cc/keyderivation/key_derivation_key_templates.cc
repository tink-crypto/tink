// Copyright 2019 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/key_derivation_key_templates.h"

#include <memory>

#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;

util::StatusOr<KeyTemplate>
KeyDerivationKeyTemplates::CreatePrfBasedKeyTemplate(
    const KeyTemplate& prf_key_template,
    const KeyTemplate& derived_key_template) {
  KeyTemplate key_template;
  key_template.set_type_url(
      internal::PrfBasedDeriverKeyManager().get_key_type());
  key_template.set_output_prefix_type(
      derived_key_template.output_prefix_type());

  PrfBasedDeriverKeyFormat format;
  *format.mutable_prf_key_template() = prf_key_template;
  *format.mutable_params()->mutable_derived_key_template() =
      derived_key_template;
  format.SerializeToString(key_template.mutable_value());

  // Verify `key_template` is derivable.
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template);
  if (!handle.ok()) {
    return handle.status();
  }
  util::StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      (*handle)->GetPrimitive<crypto::tink::KeysetDeriver>(
          ConfigGlobalRegistry());
  if (!deriver.ok()) {
    return deriver.status();
  }

  return key_template;
}

}  // namespace tink
}  // namespace crypto
