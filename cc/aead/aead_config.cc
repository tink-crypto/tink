// Copyright 2017 Google LLC
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

#include "tink/aead/aead_config.h"

#include "absl/memory/memory.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/kms_aead_key_manager.h"
#include "tink/aead/kms_envelope_aead_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/config/config_util.h"
#include "tink/mac/mac_config.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"
#include "tink/config/tink_fips.h"

using google::crypto::tink::RegistryConfig;

namespace crypto {
namespace tink {

// static
const RegistryConfig& AeadConfig::Latest() {
  static const RegistryConfig* config = new RegistryConfig();
  return *config;
}

// static
util::Status AeadConfig::Register() {
  auto status = MacConfig::Register();
  if (!status.ok()) return status;

  // Register primitive wrapper.
  status = Registry::RegisterPrimitiveWrapper(absl::make_unique<AeadWrapper>());
  if (!status.ok()) return status;

  // Register key managers which utilize the FIPS validated BoringCrypto
  // implementations.
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesCtrHmacAeadKeyManager>(), true);
  if (!status.ok()) return status;
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesGcmKeyManager>(), true);
  if (!status.ok()) return status;

  if (IsFipsModeEnabled()) {
    return util::OkStatus();
  }

  // Register all the other key managers.
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesGcmSivKeyManager>(), true);
  if (!status.ok()) return status;
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesEaxKeyManager>(), true);
  if (!status.ok()) return status;
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<XChaCha20Poly1305KeyManager>(), true);
  if (!status.ok()) return status;
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<KmsAeadKeyManager>(), true);
  if (!status.ok()) return status;
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<KmsEnvelopeAeadKeyManager>(), true);
  if (!status.ok()) return status;

  return util::OkStatus();
}




}  // namespace tink
}  // namespace crypto
