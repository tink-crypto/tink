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

#include "tink/signature/internal/config_fips_140_2.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/fips_utils.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status AddSignatureFips140_2(Configuration& config) {
  if (!IsFipsEnabledInSsl()) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "BoringSSL must be in FIPS mode.");
  }

  util::Status status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PublicKeySignWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PublicKeyVerifyWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  status = ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<EcdsaSignKeyManager>(),
      absl::make_unique<EcdsaVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<RsaSsaPkcs1VerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPssSignKeyManager>(),
      absl::make_unique<RsaSsaPssVerifyKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
