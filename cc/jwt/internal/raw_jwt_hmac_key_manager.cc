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

#include "tink/jwt/internal/raw_jwt_hmac_key_manager.h"

#include <map>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/mac.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtHmacAlgorithm;
using google::crypto::tink::JwtHmacKey;
using google::crypto::tink::JwtHmacKeyFormat;

namespace {

constexpr int kMinKeySizeInBytes = 32;

Status ValidateHmacAlgorithm(const JwtHmacAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtHmacAlgorithm::HS256:
    case JwtHmacAlgorithm::HS384:
    case JwtHmacAlgorithm::HS512:
      return util::OkStatus();
    default:
      return Status(util::error::INVALID_ARGUMENT,
                    "Unsupported algorithm.");
  }
  return util::OkStatus();
}

}  // namespace

StatusOr<JwtHmacKey> RawJwtHmacKeyManager::CreateKey(
    const JwtHmacKeyFormat& jwt_hmac_key_format) const {
  JwtHmacKey jwt_hmac_key;
  jwt_hmac_key.set_version(get_version());
  jwt_hmac_key.set_algorithm(jwt_hmac_key_format.algorithm());
  jwt_hmac_key.set_key_value(
      subtle::Random::GetRandomBytes(jwt_hmac_key_format.key_size()));
  return jwt_hmac_key;
}

StatusOr<JwtHmacKey> RawJwtHmacKeyManager::DeriveKey(
    const JwtHmacKeyFormat& jwt_hmac_key_format,
    InputStream* input_stream) const {
  return util::Status(absl::StatusCode::kUnimplemented,
                      "RawJwtHmacKeyManager::DeriveKey is not implemented");
}

Status RawJwtHmacKeyManager::ValidateKey(const JwtHmacKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().size() < kMinKeySizeInBytes) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Invalid JwtHmacKey: key_value is too short.");
  }
  return ValidateHmacAlgorithm(key.algorithm());
}

// static
Status RawJwtHmacKeyManager::ValidateKeyFormat(
    const JwtHmacKeyFormat& key_format) const {
  if (key_format.key_size() < kMinKeySizeInBytes) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Invalid HmacKeyFormat: key_size is too small.");
  }
  return ValidateHmacAlgorithm(key_format.algorithm());
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
