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
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_verify_key_manager.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using google::crypto::tink::JwtRsaSsaPkcs1PublicKey;

StatusOr<std::unique_ptr<JwtPublicKeyVerify>>
JwtRsaSsaPkcs1VerifyKeyManager::PublicKeyVerifyFactory::Create(
    const JwtRsaSsaPkcs1PublicKey& jwt_rsa_ssa_pkcs1_public_key) const {
  StatusOr<std::string> name_or =
      AlgorithmName(jwt_rsa_ssa_pkcs1_public_key.algorithm());
  if (!name_or.ok()) {
    return name_or.status();
  }
  StatusOr<std::unique_ptr<PublicKeyVerify>> verify_or =
      raw_key_manager_.GetPrimitive<PublicKeyVerify>(
          jwt_rsa_ssa_pkcs1_public_key);
  if (!verify_or.ok()) {
    return verify_or.status();
  }
  std::unique_ptr<JwtPublicKeyVerify> jwt_public_key_verify =
      absl::make_unique<jwt_internal::JwtPublicKeyVerifyImpl>(
          std::move(verify_or.ValueOrDie()), name_or.ValueOrDie());
  return jwt_public_key_verify;
}

uint32_t JwtRsaSsaPkcs1VerifyKeyManager::get_version() const {
  return raw_key_manager_.get_version();
}

google::crypto::tink::KeyData::KeyMaterialType
JwtRsaSsaPkcs1VerifyKeyManager::key_material_type() const {
  return raw_key_manager_.key_material_type();
}

const std::string& JwtRsaSsaPkcs1VerifyKeyManager::get_key_type() const {
  return raw_key_manager_.get_key_type();
}

Status JwtRsaSsaPkcs1VerifyKeyManager::ValidateKey(
    const JwtRsaSsaPkcs1PublicKey& key) const {
  return raw_key_manager_.ValidateKey(key);
}

StatusOr<std::string> JwtRsaSsaPkcs1VerifyKeyManager::AlgorithmName(
    const JwtRsaSsaPkcs1Algorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1Algorithm::RS256:
      return std::string("RS256");
    case JwtRsaSsaPkcs1Algorithm::RS384:
      return std::string("RS384");
    case JwtRsaSsaPkcs1Algorithm::RS512:
      return std::string("RS512");
    default:
      return Status(util::error::INVALID_ARGUMENT,
                    "Unsupported RSA SSA PKCS1 Algorithm");
  }
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
