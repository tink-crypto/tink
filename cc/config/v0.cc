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

#include "tink/config/v0.h"

#include "absl/log/check.h"
#include "tink/aead/internal/config_v0.h"
#include "tink/configuration.h"
#include "tink/daead/internal/config_v0.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/hybrid_decrypt_wrapper.h"
#include "tink/hybrid/hybrid_encrypt_wrapper.h"
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#include "tink/internal/configuration_impl.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/internal/chunked_mac_wrapper.h"
#include "tink/mac/mac_wrapper.h"
#include "tink/prf/internal/config_v0.h"
#include "tink/signature/internal/config_v0.h"
#include "tink/streamingaead/internal/config_v0.h"

namespace crypto {
namespace tink {
namespace {

util::Status AddMac(Configuration& config) {
  util::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<MacWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<internal::ChunkedMacWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  status = internal::ConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<HmacKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::ConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesCmacKeyManager>(), config);
}

util::Status AddHybrid(Configuration& config) {
  util::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<HybridEncryptWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<HybridDecryptWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<EciesAeadHkdfPrivateKeyManager>(),
      absl::make_unique<EciesAeadHkdfPublicKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<internal::HpkePrivateKeyManager>(),
      absl::make_unique<internal::HpkePublicKeyManager>(), config);
}

}  // namespace

const Configuration& ConfigV0() {
  static const Configuration* instance = [] {
    static Configuration* config = new Configuration();
    CHECK_OK(AddMac(*config));
    CHECK_OK(internal::AddAeadV0(*config));
    CHECK_OK(internal::AddDeterministicAeadV0(*config));
    CHECK_OK(internal::AddStreamingAeadV0(*config));
    CHECK_OK(AddHybrid(*config));
    CHECK_OK(internal::AddPrfV0(*config));
    CHECK_OK(internal::AddSignatureV0(*config));
    return config;
  }();
  return *instance;
}

}  // namespace tink
}  // namespace crypto
