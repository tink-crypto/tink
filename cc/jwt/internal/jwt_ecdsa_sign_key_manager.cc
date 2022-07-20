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
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"

#include <string>
#include <utility>

#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_public_key_sign_impl.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtEcdsaKeyFormat;
using google::crypto::tink::JwtEcdsaPrivateKey;
using google::crypto::tink::JwtEcdsaPublicKey;

StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
JwtEcdsaSignKeyManager::PublicKeySignFactory::Create(
    const JwtEcdsaPrivateKey& jwt_ecdsa_private_key) const {
  StatusOr<std::string> name = JwtEcdsaVerifyKeyManager::AlgorithmName(
      jwt_ecdsa_private_key.public_key().algorithm());
  if (!name.ok()) {
    return name.status();
  }
  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      raw_key_manager_.GetPrimitive<PublicKeySign>(jwt_ecdsa_private_key);
  if (!sign.ok()) {
    return sign.status();
  }
  absl::optional<absl::string_view> custom_kid = absl::nullopt;
  if (jwt_ecdsa_private_key.public_key().has_custom_kid()) {
    custom_kid = jwt_ecdsa_private_key.public_key().custom_kid().value();
  }
  std::unique_ptr<JwtPublicKeySignInternal> jwt_public_key_sign =
      absl::make_unique<jwt_internal::JwtPublicKeySignImpl>(*std::move(sign),
                                                            *name, custom_kid);
  return std::move(jwt_public_key_sign);
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

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
