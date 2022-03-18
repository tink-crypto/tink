// Copyright 2020 Google LLC
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
#include "tink/prf/hmac_prf_key_manager.h"

#include <set>
#include <string>

#include "absl/status/status.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/enums.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hmac_prf.pb.h"

namespace crypto {
namespace tink {
namespace {
constexpr int kMinKeySizeInBytes = 16;
}

using google::crypto::tink::HmacPrfKey;
using google::crypto::tink::HmacPrfKeyFormat;
using google::crypto::tink::HmacPrfParams;
using subtle::HashType;
using util::Enums;
using util::Status;
using util::StatusOr;

util::Status HmacPrfKeyManager::ValidateKey(const HmacPrfKey& key) const {
  util::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().size() < kMinKeySizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HmacPrfKey: key_value wrong length.");
  }
  return ValidateParams(key.params());
}

util::Status HmacPrfKeyManager::ValidateKeyFormat(
    const HmacPrfKeyFormat& key_format) const {
  util::Status status = ValidateVersion(key_format.version(), get_version());
  if (!status.ok()) return status;
  if (key_format.key_size() < kMinKeySizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HmacPrfKeyFormat: invalid key_size.");
  }
  return ValidateParams(key_format.params());
}

crypto::tink::util::StatusOr<HmacPrfKey> HmacPrfKeyManager::CreateKey(
    const HmacPrfKeyFormat& key_format) const {
  HmacPrfKey key;
  key.set_version(get_version());
  key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
  *(key.mutable_params()) = key_format.params();
  return key;
}

StatusOr<HmacPrfKey> HmacPrfKeyManager::DeriveKey(
    const HmacPrfKeyFormat& hmac_prf_key_format,
    InputStream* input_stream) const {
  crypto::tink::util::Status status = ValidateKeyFormat(hmac_prf_key_format);
  if (!status.ok()) return status;

  crypto::tink::util::StatusOr<std::string> randomness =
      ReadBytesFromStream(hmac_prf_key_format.key_size(), input_stream);
  if (!randomness.status().ok()) {
    return randomness.status();
  }

  HmacPrfKey key;
  key.set_version(get_version());
  *(key.mutable_params()) = hmac_prf_key_format.params();
  key.set_key_value(randomness.ValueOrDie());
  return key;
}

Status HmacPrfKeyManager::ValidateParams(const HmacPrfParams& params) const {
  static const std::set<HashType>* supported_hash_types =
      new std::set<HashType>({HashType::SHA1, HashType::SHA224,
                              HashType::SHA256, HashType::SHA384,
                              HashType::SHA512});
  if (supported_hash_types->find(Enums::ProtoToSubtle(params.hash())) ==
      supported_hash_types->end()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid HmacParams: HashType '%s' not supported.",
                     Enums::HashName(params.hash()));
  }
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
