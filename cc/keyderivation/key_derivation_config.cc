// Copyright 2020 Google LLC
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

#include "tink/keyderivation/key_derivation_config.h"

#include "absl/memory/memory.h"
#include "tink/config/tink_fips.h"
#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"
#include "tink/keyderivation/keyset_deriver_wrapper.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/registry.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

// static
util::Status KeyDerivationConfig::Register() {
  // Register primitive wrappers.
  util::Status status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<KeysetDeriverWrapper>());
  if (!status.ok()) {
    return status;
  }

  // Currently, no KeysetDeriver key managers only use FIPS-validated
  // implementations, so none are registered in FIPS-only mode.
  if (IsFipsModeEnabled()) {
    return util::OkStatus();
  }

  // Register required key manager for PrfBasedDeriverKeyManager.
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<HkdfPrfKeyManager>(), true);
  if (!status.ok()) {
    return status;
  }

  // Register key managers.
  return Registry::RegisterKeyTypeManager(
      absl::make_unique<internal::PrfBasedDeriverKeyManager>(), true);
}

}  // namespace tink
}  // namespace crypto
