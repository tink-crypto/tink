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
#include "tink/integration/tpm/mac/tpm_hmac_key_manager.h"

#include <memory>

#include "absl/container/flat_hash_map.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/tpm_common.pb.h"
#include "proto/tpm_hmac.pb.h"

namespace crypto {
namespace tink {
namespace integration {
namespace tpm {

namespace {

using ::crypto::tink::util::Enums;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::TpmHmacKey;
using ::google::crypto::tink::TpmHmacKeyFormat;
using ::google::crypto::tink::TpmHmacParams;
using ::google::crypto::tink::TpmObjectAuthPolicy;

constexpr int kMinTagSizeInBytes = 20;
}  // namespace

StatusOr<std::unique_ptr<Mac>> TpmHmacKeyManager::MacFactory::Create(
    const TpmHmacKey& key) const {
  return util::Status(
      util::error::UNIMPLEMENTED,
      "TpmHmacKeyManager::MacFactory::Create is not implemented");
}

Status TpmHmacKeyManager::ValidateAuthPolicy(
    const TpmObjectAuthPolicy& auth_policy) const {
  // TODO(b/191371665): Validate valid PCR selection for auth policies.
  return util::OkStatus();
}

Status TpmHmacKeyManager::ValidateParams(const TpmHmacParams& params) const {
  if (params.hmac_params().tag_size() < kMinTagSizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid HmacParams: tag size %d is too small.",
                     params.hmac_params().tag_size());
  }

  // Most TPMs support the following algorithms.
  absl::flat_hash_map<HashType, int> max_tag_size = {
      {HashType::SHA1, 20}, {HashType::SHA256, 32}, {HashType::SHA384, 48}};

  if (max_tag_size.find(params.hmac_params().hash()) == max_tag_size.end()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid HmacParams: HashType '%s' not supported.",
                     Enums::HashName(params.hmac_params().hash()));
  }
  if (params.hmac_params().tag_size() >
      max_tag_size[params.hmac_params().hash()]) {
    return ToStatusF(
        util::error::INVALID_ARGUMENT,
        "Invalid HmacParams: tag_size %d is too big for HashType '%s'.",
        params.hmac_params().tag_size(),
        Enums::HashName(params.hmac_params().hash()));
  }
  return ValidateAuthPolicy(params.auth_policy());
}

Status TpmHmacKeyManager::ValidateKey(const TpmHmacKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  // Key is derived by the TPM (using a KDF) based on the chosen hash function.
  // The key size is determined on the hash algorithm digest size.
  return ValidateParams(key.params());
}

Status TpmHmacKeyManager::ValidateKeyFormat(
    const TpmHmacKeyFormat& key_format) const {
  return ValidateParams(key_format.params());
}

StatusOr<TpmHmacKey> TpmHmacKeyManager::CreateKey(
    const TpmHmacKeyFormat& key_format) const {
  return util::Status(util::error::UNIMPLEMENTED,
                      "TpmHmacKeyManager::CreateKey is not implemented");
}

}  // namespace tpm
}  // namespace integration
}  // namespace tink
}  // namespace crypto
