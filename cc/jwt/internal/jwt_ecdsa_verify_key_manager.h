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
#ifndef TINK_JWT_INTERNAL_JWT_ECDSA_VERIFY_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_JWT_ECDSA_VERIFY_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "tink/core/key_type_manager.h"
#include "tink/jwt/internal/jwt_public_key_verify_impl.h"
#include "tink/jwt/internal/raw_jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/jwt_ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {


class JwtEcdsaVerifyKeyManager
    : public KeyTypeManager<google::crypto::tink::JwtEcdsaPublicKey, void,
                            List<JwtPublicKeyVerify>> {
 public:
  class PublicKeyVerifyFactory : public PrimitiveFactory<JwtPublicKeyVerify> {
    crypto::tink::util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> Create(
        const google::crypto::tink::JwtEcdsaPublicKey& jwt_ecdsa_public_key)
        const override;
   private:
    const RawJwtEcdsaVerifyKeyManager raw_key_manager_;
  };

  JwtEcdsaVerifyKeyManager()
      : KeyTypeManager(absl::make_unique<PublicKeyVerifyFactory>()) {}

  uint32_t get_version() const override;

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override;

  const std::string& get_key_type() const override;

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::JwtEcdsaPublicKey& key) const override;

 private:
  const RawJwtEcdsaVerifyKeyManager raw_key_manager_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_ECDSA_VERIFY_KEY_MANAGER_H_
