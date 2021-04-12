// Copyright 2021 Google LLC.
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


namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtEcdsaPublicKey;


StatusOr<std::unique_ptr<JwtPublicKeyVerify>>
JwtEcdsaVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const JwtEcdsaPublicKey& jwt_ecdsa_public_key) const {
  std::string algorithm;
  switch (jwt_ecdsa_public_key.algorithm()) {
    case google::crypto::tink::JwtEcdsaAlgorithm::ES256:
      algorithm = "ES256";
      break;
    case google::crypto::tink::JwtEcdsaAlgorithm::ES384:
      algorithm = "ES384";
      break;
    case google::crypto::tink::JwtEcdsaAlgorithm::ES512:
      algorithm = "ES512";
      break;
    default:
      return util::Status(util::error::INVALID_ARGUMENT, "Unknown algorithm");
  }
  auto result =
      raw_key_manager_.GetPrimitive<PublicKeyVerify>(jwt_ecdsa_public_key);
  if (!result.ok()) {
    return result.status();
  }
  std::unique_ptr<JwtPublicKeyVerify> jwt_public_key_verify =
      absl::make_unique<jwt_internal::JwtPublicKeyVerifyImpl>(
          std::move(result.ValueOrDie()), algorithm);
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

}  // namespace tink
}  // namespace crypto
