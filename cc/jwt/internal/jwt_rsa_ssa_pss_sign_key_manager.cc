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
#include "tink/jwt/internal/jwt_rsa_ssa_pss_sign_key_manager.h"

#include "tink/jwt/internal/jwt_public_key_sign_impl.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_verify_key_manager.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtRsaSsaPssKeyFormat;
using google::crypto::tink::JwtRsaSsaPssPrivateKey;
using google::crypto::tink::JwtRsaSsaPssPublicKey;

StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
JwtRsaSsaPssSignKeyManager::PublicKeySignFactory::Create(
    const JwtRsaSsaPssPrivateKey& jwt_rsa_ssa_pss_private_key) const {
  StatusOr<std::string> name_or = JwtRsaSsaPssVerifyKeyManager::AlgorithmName(
      jwt_rsa_ssa_pss_private_key.public_key().algorithm());
  if (!name_or.ok()) {
    return name_or.status();
  }
  StatusOr<std::unique_ptr<PublicKeySign>> sign_or =
      raw_key_manager_.GetPrimitive<PublicKeySign>(jwt_rsa_ssa_pss_private_key);
  if (!sign_or.ok()) {
    return sign_or.status();
  }
  std::unique_ptr<JwtPublicKeySignInternal> jwt_public_key_sign =
      absl::make_unique<jwt_internal::JwtPublicKeySignImpl>(
          std::move(sign_or.ValueOrDie()), name_or.ValueOrDie());
  return jwt_public_key_sign;
}

uint32_t JwtRsaSsaPssSignKeyManager::get_version() const {
  return raw_key_manager_.get_version();
}

google::crypto::tink::KeyData::KeyMaterialType
JwtRsaSsaPssSignKeyManager::key_material_type() const {
  return raw_key_manager_.key_material_type();
}

const std::string& JwtRsaSsaPssSignKeyManager::get_key_type() const {
  return raw_key_manager_.get_key_type();
}

StatusOr<JwtRsaSsaPssPrivateKey> JwtRsaSsaPssSignKeyManager::CreateKey(
    const JwtRsaSsaPssKeyFormat& key_format) const {
  return raw_key_manager_.CreateKey(key_format);
}

Status JwtRsaSsaPssSignKeyManager::ValidateKey(
    const JwtRsaSsaPssPrivateKey& key) const {
  return raw_key_manager_.ValidateKey(key);
}

Status JwtRsaSsaPssSignKeyManager::ValidateKeyFormat(
    const JwtRsaSsaPssKeyFormat& key_format) const {
  return raw_key_manager_.ValidateKeyFormat(key_format);
}

StatusOr<JwtRsaSsaPssPublicKey> JwtRsaSsaPssSignKeyManager::GetPublicKey(
    const JwtRsaSsaPssPrivateKey& private_key) const {
  return raw_key_manager_.GetPublicKey(private_key);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
