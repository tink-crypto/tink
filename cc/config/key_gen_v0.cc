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

#include "tink/config/key_gen_v0.h"

#include "absl/log/check.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/configuration.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_sign_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/signature/ecdsa_sign_key_manager.h"

namespace crypto {
namespace tink {
namespace {

util::Status AddMac(KeyGenConfiguration& config) {
  util::Status status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<HmacKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesCmacKeyManager>(), config);
}

util::Status AddAead(KeyGenConfiguration& config) {
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

util::Status AddDeterministicAead(KeyGenConfiguration& config) {
  return internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesSivKeyManager>(), config);
}

util::Status AddStreamingAead(KeyGenConfiguration& config) {
  util::Status status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesGcmHkdfStreamingKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesCtrHmacStreamingKeyManager>(), config);
}

util::Status AddHybrid(KeyGenConfiguration& config) {
  util::Status status =
      internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
          absl::make_unique<EciesAeadHkdfPrivateKeyManager>(),
          absl::make_unique<EciesAeadHkdfPublicKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<internal::HpkePrivateKeyManager>(),
      absl::make_unique<internal::HpkePublicKeyManager>(), config);
}

util::Status AddPrf(KeyGenConfiguration& config) {
  util::Status status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<HmacPrfKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<HkdfPrfKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesCmacPrfKeyManager>(), config);
}

util::Status AddSignature(KeyGenConfiguration& config) {
  util::Status status =
      internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
          absl::make_unique<EcdsaSignKeyManager>(),
          absl::make_unique<EcdsaVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPssSignKeyManager>(),
      absl::make_unique<RsaSsaPssVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<RsaSsaPkcs1VerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<Ed25519SignKeyManager>(),
      absl::make_unique<Ed25519VerifyKeyManager>(), config);
}

}  // namespace

const KeyGenConfiguration& KeyGenConfigV0() {
  static const KeyGenConfiguration* instance = [] {
    static KeyGenConfiguration* config = new KeyGenConfiguration();
    CHECK_OK(AddMac(*config));
    CHECK_OK(AddAead(*config));
    CHECK_OK(AddDeterministicAead(*config));
    CHECK_OK(AddStreamingAead(*config));
    CHECK_OK(AddHybrid(*config));
    CHECK_OK(AddPrf(*config));
    CHECK_OK(AddSignature(*config));
    return config;
  }();
  return *instance;
}

}  // namespace tink
}  // namespace crypto
