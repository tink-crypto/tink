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

#include "tink/jwt/internal/raw_jwt_ecdsa_verify_key_manager.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
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
using google::crypto::tink::JwtEcdsaAlgorithm;
using google::crypto::tink::JwtEcdsaPublicKey;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;

StatusOr<std::unique_ptr<PublicKeyVerify>>
RawJwtEcdsaVerifyKeyManager::PublicKeyVerifyFactory::Create(
      const JwtEcdsaPublicKey& jwt_ecdsa_public_key) const {
  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  util::StatusOr<google::crypto::tink::EllipticCurveType> curve =
      CurveForEcdsaAlgorithm(jwt_ecdsa_public_key.algorithm());
  if (!curve.ok()) {
    return curve.status();
  }
  ec_key.curve = Enums::ProtoToSubtle(*curve);
  ec_key.pub_x = jwt_ecdsa_public_key.x();
  ec_key.pub_y = jwt_ecdsa_public_key.y();
  util::StatusOr<google::crypto::tink::HashType> hash_type =
      HashForEcdsaAlgorithm(jwt_ecdsa_public_key.algorithm());
  if (!hash_type.ok()) {
    return hash_type.status();
  }
  auto result = subtle::EcdsaVerifyBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(*hash_type),
      subtle::EcdsaSignatureEncoding::IEEE_P1363);
  if (!result.ok()) return result.status();
  return {*std::move(result)};
}

StatusOr<EllipticCurveType>
RawJwtEcdsaVerifyKeyManager::CurveForEcdsaAlgorithm(
    const JwtEcdsaAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
      return EllipticCurveType::NIST_P256;
    case JwtEcdsaAlgorithm::ES384:
      return EllipticCurveType::NIST_P384;
    case JwtEcdsaAlgorithm::ES512:
      return EllipticCurveType::NIST_P521;
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Unsupported Ecdsa Algorithm");
  }
}

StatusOr<HashType> RawJwtEcdsaVerifyKeyManager::HashForEcdsaAlgorithm(
    const JwtEcdsaAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
      return HashType::SHA256;
    case JwtEcdsaAlgorithm::ES384:
      return HashType::SHA384;
    case JwtEcdsaAlgorithm::ES512:
      return HashType::SHA512;
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Unsupported Ecdsa Algorithm");
  }
}

Status RawJwtEcdsaVerifyKeyManager::ValidateAlgorithm(
    const JwtEcdsaAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
    case JwtEcdsaAlgorithm::ES384:
    case JwtEcdsaAlgorithm::ES512:
      return util::OkStatus();
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Unsupported Ecdsa Algorithm");
  }
  return util::OkStatus();
}

Status RawJwtEcdsaVerifyKeyManager::ValidateKey(
    const JwtEcdsaPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return ValidateAlgorithm(key.algorithm());
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
