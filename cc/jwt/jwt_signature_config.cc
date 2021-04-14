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

#include "tink/jwt/jwt_signature_config.h"

#include "absl/memory/memory.h"
#include "tink/config/config_util.h"
#include "tink/config/tink_fips.h"
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_public_key_sign_wrapper.h"
#include "tink/jwt/internal/jwt_public_key_verify_wrapper.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

// static
util::Status JwtSignatureRegister() {
  // Register primitive wrappers.
  auto status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<jwt_internal::JwtPublicKeySignWrapper>());
  if (!status.ok()) return status;
  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<jwt_internal::JwtPublicKeyVerifyWrapper>());
  if (!status.ok()) return status;

  // Register key managers which utilize FIPS validated BoringCrypto
  // implementations.
  // ECDSA
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<jwt_internal::JwtEcdsaSignKeyManager>(),
      absl::make_unique<jwt_internal::JwtEcdsaVerifyKeyManager>(), true);
  if (!status.ok()) return status;
  // RSA SSA PKCS1
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<jwt_internal::JwtRsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<jwt_internal::JwtRsaSsaPkcs1VerifyKeyManager>(), true);
  if (!status.ok()) return status;

  if (kUseOnlyFips) {
    return util::OkStatus();
  }

  // There are currently no non-FIPS key managers.

  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
