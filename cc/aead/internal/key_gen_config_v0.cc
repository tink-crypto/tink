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

#include "tink/aead/internal/key_gen_config_v0.h"

#include "absl/memory/memory.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key_gen_configuration.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status AddAeadKeyGenV0(KeyGenConfiguration& config) {
  // TODO(b/296630956): Alphabetize in all AEAD config files.
  util::Status status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesCtrHmacAeadKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesGcmKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesGcmSivKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesEaxKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<XChaCha20Poly1305KeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
