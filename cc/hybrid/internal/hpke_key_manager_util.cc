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

#include "tink/hybrid/internal/hpke_key_manager_util.h"

#include "absl/status/status.h"
#include "tink/util/status.h"
#include "tink/util/validation.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::HpkePublicKey;

util::Status ValidateParams(const HpkeParams& params) {
  if (params.kem() == HpkeKem::KEM_UNKNOWN) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid KEM param.");
  }
  if (params.kdf() == HpkeKdf::KDF_UNKNOWN) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid KDF param.");
  }
  if (params.aead() == HpkeAead::AEAD_UNKNOWN) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid AEAD param.");
  }
  return util::OkStatus();
}

util::Status ValidateKeyAndVersion(const HpkePublicKey& key,
                                   uint32_t max_key_version) {
  util::Status status = ValidateVersion(key.version(), max_key_version);
  if (!status.ok()) return status;
  if (!key.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing HPKE key params.");
  }
  return ValidateParams(key.params());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
