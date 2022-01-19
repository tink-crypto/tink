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

#include "tink/hybrid/hpke_config.h"

#include "tink/aead/aead_config.h"
#include "tink/config/tink_fips.h"
#include "tink/hybrid/hybrid_decrypt_wrapper.h"
#include "tink/hybrid/hybrid_encrypt_wrapper.h"
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#include "tink/registry.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

util::Status RegisterHpke() {
  util::Status status = AeadConfig::Register();

  // Register primitive wrappers.
  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<HybridEncryptWrapper>());
  if (!status.ok()) return status;
  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<HybridDecryptWrapper>());
  if (!status.ok()) return status;

  // Currently there are no HPKE key managers which only use FIPS-validated
  // implementations, therefore none will be registered in FIPS-only mode.
  if (IsFipsModeEnabled()) {
    return util::OkStatus();
  }

  // Register non-FIPS HPKE key managers.
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<internal::HpkePrivateKeyManager>(),
      absl::make_unique<internal::HpkePublicKeyManager>(), true);
  return status;
}

}  // namespace tink
}  // namespace crypto

