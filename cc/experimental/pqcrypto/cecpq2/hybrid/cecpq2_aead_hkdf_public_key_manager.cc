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

#include "tink/experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_public_key_manager.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/cecpq2/hybrid/internal/cecpq2_aead_hkdf_hybrid_encrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/experimental/pqcrypto/cecpq2_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using google::crypto::tink::Cecpq2AeadHkdfParams;
using google::crypto::tink::Cecpq2AeadHkdfPublicKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;

Status Cecpq2AeadHkdfPublicKeyManager::ValidateParams(
    const Cecpq2AeadHkdfParams& params) const {
  // Validate KEM params
  if (!params.has_kem_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing kem_params.");
  }
  if (params.kem_params().curve_type() == EllipticCurveType::UNKNOWN_CURVE ||
      params.kem_params().curve_type() != EllipticCurveType::CURVE25519 ||
      params.kem_params().hkdf_hash_type() == HashType::UNKNOWN_HASH) {
    return Status(absl::StatusCode::kInvalidArgument, "Invalid kem_params.");
  }

  // Validate DEM params
  if (!params.has_dem_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing dem_params.");
  }
  if (!params.dem_params().has_aead_dem()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "dem_params has no aead_dem.");
  }

  // Validate EC point format
  if (params.kem_params().ec_point_format() == EcPointFormat::UNKNOWN_FORMAT) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Unknown EC point format.");
  }
  return util::OkStatus();
}

Status Cecpq2AeadHkdfPublicKeyManager::ValidateKey(
    const Cecpq2AeadHkdfPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (!key.has_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing params.");
  }
  return ValidateParams(key.params());
}

}  // namespace tink
}  // namespace crypto
