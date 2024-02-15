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
///////////////////////////////////////////////////////////////////////////////

#include "tink/config/fips_140_2.h"

#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/internal/chunked_mac_wrapper.h"
#include "tink/mac/mac_wrapper.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/prf_set_wrapper.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/util/status.h"
#include "tink/signature/ecdsa_sign_key_manager.h"

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

  return internal::ConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<HmacKeyManager>(), config);
}

util::Status AddAead(Configuration& config) {
  util::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<AeadWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  status = internal::ConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesCtrHmacAeadKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::ConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesGcmKeyManager>(), config);
}

util::Status AddPrf(Configuration& config) {
  util::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PrfSetWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  return internal::ConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<HmacPrfKeyManager>(), config);
}

util::Status AddSignature(Configuration& config) {
  util::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PublicKeySignWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PublicKeyVerifyWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<EcdsaSignKeyManager>(),
      absl::make_unique<EcdsaVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPssSignKeyManager>(),
      absl::make_unique<RsaSsaPssVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<RsaSsaPkcs1VerifyKeyManager>(), config);
}

}  // namespace

const Configuration& ConfigFips140_2() {
  static const Configuration* instance = [] {
    internal::SetFipsRestricted();

    static Configuration* config = new Configuration();
    CHECK_OK(AddMac(*config));
    CHECK_OK(AddAead(*config));
    CHECK_OK(AddPrf(*config));
    CHECK_OK(AddSignature(*config));

    return config;
  }();
  return *instance;
}

}  // namespace tink
}  // namespace crypto
