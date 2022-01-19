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
#ifndef TINK_JWT_INTERNAL_RAW_JWT_ECDSA_VERIFY_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_RAW_JWT_ECDSA_VERIFY_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/public_key_verify.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/jwt_ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class RawJwtEcdsaVerifyKeyManager
    : public KeyTypeManager<google::crypto::tink::JwtEcdsaPublicKey, void,
                            List<PublicKeyVerify>> {
 public:
  class PublicKeyVerifyFactory : public PrimitiveFactory<PublicKeyVerify> {
    crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>> Create(
        const google::crypto::tink::JwtEcdsaPublicKey& jwt_ecdsa_public_key)
        const override;
  };

  RawJwtEcdsaVerifyKeyManager()
      : KeyTypeManager(absl::make_unique<PublicKeyVerifyFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::JwtEcdsaPublicKey& key) const override;

 private:
  static crypto::tink::util::Status ValidateAlgorithm(
      const google::crypto::tink::JwtEcdsaAlgorithm& algorithm);

  static crypto::tink::util::StatusOr<google::crypto::tink::EllipticCurveType>
  CurveForEcdsaAlgorithm(
      const google::crypto::tink::JwtEcdsaAlgorithm& algorithm);

  static crypto::tink::util::StatusOr<google::crypto::tink::HashType>
  HashForEcdsaAlgorithm(
      const google::crypto::tink::JwtEcdsaAlgorithm& algorithm);

  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom,
                   google::crypto::tink::JwtEcdsaPublicKey().GetTypeName());
  friend class RawJwtEcdsaSignKeyManager;
};

}  // namespace jwt_internal

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_RAW_JWT_ECDSA_VERIFY_KEY_MANAGER_H_
