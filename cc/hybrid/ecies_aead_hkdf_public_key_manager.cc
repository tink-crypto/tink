// Copyright 2017 Google Inc.
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

#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/key_manager.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using google::crypto::tink::EciesAeadHkdfParams;
using google::crypto::tink::EciesAeadHkdfPublicKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;

Status EciesAeadHkdfPublicKeyManager::ValidateParams(
    const EciesAeadHkdfParams& params) const {
  // Validate KEM params.
  if (!params.has_kem_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing kem_params.");
  }
  if (params.kem_params().curve_type() == EllipticCurveType::UNKNOWN_CURVE ||
      params.kem_params().hkdf_hash_type() == HashType::UNKNOWN_HASH) {
    return Status(absl::StatusCode::kInvalidArgument, "Invalid kem_params.");
  }

  // Validate DEM params.
  if (!params.has_dem_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing dem_params.");
  }
  if (!params.dem_params().has_aead_dem()) {
    return Status(absl::StatusCode::kInvalidArgument, "Invalid dem_params.");
  }

  // Validate EC point format.
  if (params.ec_point_format() == EcPointFormat::UNKNOWN_FORMAT) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Unknown EC point format.");
  }
  return util::OkStatus();
}

Status EciesAeadHkdfPublicKeyManager::ValidateKey(
    const EciesAeadHkdfPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (!key.has_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing params.");
  }
  return ValidateParams(key.params());
}


}  // namespace tink
}  // namespace crypto
