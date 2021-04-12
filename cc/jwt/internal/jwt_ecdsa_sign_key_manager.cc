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
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtEcdsaKeyFormat;
using google::crypto::tink::JwtEcdsaPrivateKey;
using google::crypto::tink::JwtEcdsaPublicKey;

StatusOr<std::unique_ptr<JwtPublicKeySign>>
JwtEcdsaSignKeyManager::PublicKeySignFactory::Create(
    const JwtEcdsaPrivateKey& jwt_ecdsa_private_key) const {
  std::string algorithm;
  switch (jwt_ecdsa_private_key.public_key().algorithm()) {
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
      raw_key_manager_.GetPrimitive<PublicKeySign>(jwt_ecdsa_private_key);
  if (!result.ok()) {
    return result.status();
  }
  std::unique_ptr<JwtPublicKeySign> jwt_public_key_sign =
      absl::make_unique<jwt_internal::JwtPublicKeySignImpl>(
          std::move(result.ValueOrDie()), algorithm);
  return jwt_public_key_sign;
}

uint32_t JwtEcdsaSignKeyManager::get_version() const {
  return raw_key_manager_.get_version();
}

google::crypto::tink::KeyData::KeyMaterialType
JwtEcdsaSignKeyManager::key_material_type() const {
  return raw_key_manager_.key_material_type();
}

const std::string& JwtEcdsaSignKeyManager::get_key_type() const {
  return raw_key_manager_.get_key_type();
}

StatusOr<JwtEcdsaPrivateKey> JwtEcdsaSignKeyManager::CreateKey(
    const JwtEcdsaKeyFormat& key_format) const {
  return raw_key_manager_.CreateKey(key_format);
}

Status JwtEcdsaSignKeyManager::ValidateKey(
    const JwtEcdsaPrivateKey& key) const {
  return raw_key_manager_.ValidateKey(key);
}

Status JwtEcdsaSignKeyManager::ValidateKeyFormat(
    const JwtEcdsaKeyFormat& key_format) const {
  return raw_key_manager_.ValidateKeyFormat(key_format);
}

StatusOr<JwtEcdsaPublicKey> JwtEcdsaSignKeyManager::GetPublicKey(
    const JwtEcdsaPrivateKey& private_key) const {
  return raw_key_manager_.GetPublicKey(private_key);
}

}  // namespace tink
}  // namespace crypto
