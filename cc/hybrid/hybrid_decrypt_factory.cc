// Copyright 2017 Google Inc.
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

#include "cc/hybrid/hybrid_decrypt_factory.h"

#include "cc/hybrid_decrypt.h"
#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/registry.h"
#include "cc/aead/aes_gcm_key_manager.h"
#include "cc/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "cc/hybrid/hybrid_decrypt_set_wrapper.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"

namespace crypto {
namespace tink {

// static
util::Status HybridDecryptFactory::RegisterStandardKeyTypes() {
  auto aes_gcm_key_manager = new AesGcmKeyManager();
  // We intentionally ignore the status of registration of AesGcmKeyManager,
  // as the registration may fail if AeadFactory::RegisterStandardKeyTypes()
  // was called before.
  // TODO(przydatek): this is not really a good solution,
  //     find a better way of dealing with such situations.
  util::Status status = Registry::get_default_registry().RegisterKeyManager(
      aes_gcm_key_manager->get_key_type(), aes_gcm_key_manager);
  auto ecies_key_manager = new EciesAeadHkdfPrivateKeyManager();
  status = Registry::get_default_registry().RegisterKeyManager(
      ecies_key_manager->get_key_type(), ecies_key_manager);
  return status;
}

// static
util::Status HybridDecryptFactory::RegisterLegacyKeyTypes() {
  return util::Status::OK;
}

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>>
HybridDecryptFactory::GetPrimitive(const KeysetHandle& keyset_handle) {
  return GetPrimitive(keyset_handle, nullptr);
}

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>>
HybridDecryptFactory::GetPrimitive(const KeysetHandle& keyset_handle,
    const KeyManager<HybridDecrypt>* custom_key_manager) {
  auto primitives_result = Registry::get_default_registry()
      .GetPrimitives<HybridDecrypt>(keyset_handle, custom_key_manager);
  if (primitives_result.ok()) {
    return HybridDecryptSetWrapper::NewHybridDecrypt(
        std::move(primitives_result.ValueOrDie()));
  }
  return primitives_result.status();
}

}  // namespace tink
}  // namespace crypto
