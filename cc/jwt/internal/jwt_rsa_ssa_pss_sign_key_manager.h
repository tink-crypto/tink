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
#ifndef TINK_JWT_INTERNAL_JWT_RSA_SSA_PSS_SIGN_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_JWT_RSA_SSA_PSS_SIGN_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/internal/raw_jwt_rsa_ssa_pss_sign_key_manager.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class JwtRsaSsaPssSignKeyManager
    : public PrivateKeyTypeManager<google::crypto::tink::JwtRsaSsaPssPrivateKey,
                                   google::crypto::tink::JwtRsaSsaPssKeyFormat,
                                   google::crypto::tink::JwtRsaSsaPssPublicKey,
                                   List<JwtPublicKeySignInternal>> {
 public:
  class PublicKeySignFactory
      : public PrimitiveFactory<JwtPublicKeySignInternal> {
    crypto::tink::util::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
    Create(const google::crypto::tink::JwtRsaSsaPssPrivateKey& private_key)
        const override;

   private:
    const RawJwtRsaSsaPssSignKeyManager raw_key_manager_;
  };

  JwtRsaSsaPssSignKeyManager()
      : PrivateKeyTypeManager(absl::make_unique<PublicKeySignFactory>()) {}

  uint32_t get_version() const override;

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override;

  const std::string& get_key_type() const override;

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::JwtRsaSsaPssPrivateKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::JwtRsaSsaPssKeyFormat& key_format)
      const override;

  crypto::tink::util::StatusOr<google::crypto::tink::JwtRsaSsaPssPrivateKey>
  CreateKey(const google::crypto::tink::JwtRsaSsaPssKeyFormat& key_format)
      const override;

  crypto::tink::util::StatusOr<google::crypto::tink::JwtRsaSsaPssPublicKey>
  GetPublicKey(const google::crypto::tink::JwtRsaSsaPssPrivateKey& private_key)
      const override;

 private:
  const RawJwtRsaSsaPssSignKeyManager raw_key_manager_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_RSA_SSA_PSS_SIGN_KEY_MANAGER_H_
