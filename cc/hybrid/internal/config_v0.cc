// Copyright 2023 Google LLC
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

#include "tink/hybrid/internal/config_v0.h"

#include "absl/memory/memory.h"
#include "tink/configuration.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/hybrid_decrypt_wrapper.h"
#include "tink/hybrid/hybrid_encrypt_wrapper.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#endif
#include "tink/internal/configuration_impl.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status AddHybridV0(Configuration& config) {
  util::Status status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<HybridEncryptWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<HybridDecryptWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

#ifdef OPENSSL_IS_BORINGSSL
  status = ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<HpkePrivateKeyManager>(),
      absl::make_unique<HpkePublicKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
#endif
  return ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<EciesAeadHkdfPrivateKeyManager>(),
      absl::make_unique<EciesAeadHkdfPublicKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
