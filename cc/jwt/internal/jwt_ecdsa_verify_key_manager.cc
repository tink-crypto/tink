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
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"

#include <string>
#include <utility>

#include "absl/status/status.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtEcdsaPublicKey;
using google::crypto::tink::JwtEcdsaAlgorithm;

StatusOr<std::unique_ptr<JwtPublicKeyVerifyInternal>>
JwtEcdsaVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const JwtEcdsaPublicKey& jwt_ecdsa_public_key) const {
  StatusOr<std::string> name = AlgorithmName(jwt_ecdsa_public_key.algorithm());
  if (!name.ok()) {
    return name.status();
  }
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      raw_key_manager_.GetPrimitive<PublicKeyVerify>(jwt_ecdsa_public_key);
  if (!verify.ok()) {
    return verify.status();
  }
  absl::optional<absl::string_view> custom_kid = absl::nullopt;
  if (jwt_ecdsa_public_key.has_custom_kid()) {
    custom_kid = jwt_ecdsa_public_key.custom_kid().value();
  }
  std::unique_ptr<JwtPublicKeyVerifyInternal> jwt_public_key_verify =
      absl::make_unique<jwt_internal::JwtPublicKeyVerifyImpl>(
          *std::move(verify), *name, custom_kid);
  return jwt_public_key_verify;
}

uint32_t JwtEcdsaVerifyKeyManager::get_version() const {
  return raw_key_manager_.get_version();
}

google::crypto::tink::KeyData::KeyMaterialType
JwtEcdsaVerifyKeyManager::key_material_type() const {
  return raw_key_manager_.key_material_type();
}

const std::string& JwtEcdsaVerifyKeyManager::get_key_type() const {
  return raw_key_manager_.get_key_type();
}

Status JwtEcdsaVerifyKeyManager::ValidateKey(
    const JwtEcdsaPublicKey& key) const {
  return raw_key_manager_.ValidateKey(key);
}

StatusOr<std::string> JwtEcdsaVerifyKeyManager::AlgorithmName(
    const JwtEcdsaAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
      return std::string("ES256");
    case JwtEcdsaAlgorithm::ES384:
      return std::string("ES384");
    case JwtEcdsaAlgorithm::ES512:
      return std::string("ES512");
    default:
      return Status(absl::StatusCode::kInvalidArgument, "Unknown algorithm");
  }
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
