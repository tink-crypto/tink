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

#include "tink/experimental/pqcrypto/signature/signature_config.h"

#include "absl/memory/memory.h"
#include "tink/config/config_util.h"
#include "tink/config/tink_fips.h"
#include "tink/experimental/pqcrypto/signature/dilithium_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/dilithium_verify_key_manager.h"
#include "tink/experimental/pqcrypto/signature/sphincs_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/sphincs_verify_key_manager.h"
#include "tink/registry.h"
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

util::Status PqSignatureConfigRegister() {
  // Register primitive wrappers.
  auto status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<PublicKeySignWrapper>());
  if (!status.ok()) return status;
  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<PublicKeyVerifyWrapper>());
  if (!status.ok()) return status;

  if (IsFipsModeEnabled()) {
    return util::OkStatus();
  }

  // Dilithium
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<DilithiumSignKeyManager>(),
      absl::make_unique<DilithiumVerifyKeyManager>(), true);

  // Sphincs
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<SphincsSignKeyManager>(),
      absl::make_unique<SphincsVerifyKeyManager>(), true);
  return status;
}

}  // namespace tink
}  // namespace crypto
