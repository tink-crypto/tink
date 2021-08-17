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

#include "tink/jwt/internal/raw_jwt_ecdsa_sign_key_manager.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/jwt/internal/raw_jwt_ecdsa_verify_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/jwt_ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtEcdsaKeyFormat;
using google::crypto::tink::JwtEcdsaPrivateKey;
using google::crypto::tink::JwtEcdsaPublicKey;

StatusOr<JwtEcdsaPrivateKey> RawJwtEcdsaSignKeyManager::CreateKey(
    const JwtEcdsaKeyFormat& jwt_ecdsa_key_format) const {
  // Generate new EC key.
  util::StatusOr<google::crypto::tink::EllipticCurveType> curve =
      RawJwtEcdsaVerifyKeyManager::CurveForEcdsaAlgorithm(
          jwt_ecdsa_key_format.algorithm());
  if (!curve.ok()) {
    return curve.status();
  }

  util::StatusOr<subtle::SubtleUtilBoringSSL::EcKey> ec_key =
      subtle::SubtleUtilBoringSSL::GetNewEcKey(
          util::Enums::ProtoToSubtle(*curve));
  if (!ec_key.ok()) return ec_key.status();

  // Build EcdsaPrivateKey.
  JwtEcdsaPrivateKey jwt_ecdsa_private_key;
  jwt_ecdsa_private_key.set_version(get_version());
  jwt_ecdsa_private_key.set_key_value(
      std::string(util::SecretDataAsStringView(ec_key->priv)));
  auto jwt_ecdsa_public_key = jwt_ecdsa_private_key.mutable_public_key();
  jwt_ecdsa_public_key->set_version(get_version());
  jwt_ecdsa_public_key->set_x(ec_key->pub_x);
  jwt_ecdsa_public_key->set_y(ec_key->pub_y);
  jwt_ecdsa_public_key->set_algorithm(jwt_ecdsa_key_format.algorithm());
  return jwt_ecdsa_private_key;
}

StatusOr<std::unique_ptr<PublicKeySign>>
RawJwtEcdsaSignKeyManager::PublicKeySignFactory::Create(
    const JwtEcdsaPrivateKey& jwt_ecdsa_private_key) const {
  const JwtEcdsaPublicKey& public_key = jwt_ecdsa_private_key.public_key();
  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  util::StatusOr<google::crypto::tink::EllipticCurveType> curve =
      RawJwtEcdsaVerifyKeyManager::CurveForEcdsaAlgorithm(
          public_key.algorithm());
  if (!curve.ok()) {
    return curve.status();
  }
  ec_key.curve = Enums::ProtoToSubtle(*curve);
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  ec_key.priv =
      util::SecretDataFromStringView(jwt_ecdsa_private_key.key_value());
  util::StatusOr<google::crypto::tink::HashType> hash_type =
      RawJwtEcdsaVerifyKeyManager::HashForEcdsaAlgorithm(
          public_key.algorithm());
  if (!hash_type.ok()) {
    return hash_type.status();
  }
  auto result = subtle::EcdsaSignBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(*hash_type),
      subtle::EcdsaSignatureEncoding::IEEE_P1363);
  if (!result.ok()) return result.status();
  return {*std::move(result)};
}

Status RawJwtEcdsaSignKeyManager::ValidateKey(
    const JwtEcdsaPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return RawJwtEcdsaVerifyKeyManager().ValidateKey(key.public_key());
}

Status RawJwtEcdsaSignKeyManager::ValidateKeyFormat(
    const JwtEcdsaKeyFormat& key_format) const {
  return RawJwtEcdsaVerifyKeyManager::ValidateAlgorithm(key_format.algorithm());
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
