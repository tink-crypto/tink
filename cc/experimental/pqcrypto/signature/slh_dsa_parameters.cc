// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"

#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<SlhDsaParameters> SlhDsaParameters::Create(
    HashType hash_type, int private_key_size_in_bytes,
    SignatureType signature_type, Variant variant) {
  // Validate HashType - only SHA2 is currently supported.
  if (hash_type != HashType::kSha2) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create Slh-DSA parameters with unknown HashType.");
  }

  if (private_key_size_in_bytes != 64) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid private key size. Only 64-bytes keys are "
                        "currently supported.");
  }

  // Validate SignatureType - only SmallSignature is currently supported.
  if (signature_type != SignatureType::kSmallSignature) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create SLH-DSA parameters with unknown SignatureType.");
  }

  // Validate Variant.
  if (variant != Variant::kTink && variant != Variant::kNoPrefix) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create SLH-DSA parameters with unknown Variant.");
  }
  return SlhDsaParameters(hash_type, private_key_size_in_bytes, signature_type,
                          variant);
}

bool SlhDsaParameters::operator==(const Parameters& other) const {
  const SlhDsaParameters* that = dynamic_cast<const SlhDsaParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return hash_type_ == that->hash_type_ &&
         private_key_size_in_bytes_ == that->private_key_size_in_bytes_ &&
         signature_type_ == that->signature_type_ && variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
