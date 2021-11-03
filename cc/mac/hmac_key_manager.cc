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

#include "tink/mac/hmac_key_manager.h"

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
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::HashType;
using google::crypto::tink::HmacKey;
using google::crypto::tink::HmacKeyFormat;
using google::crypto::tink::HmacParams;

namespace {

constexpr int kMinKeySizeInBytes = 16;
constexpr int kMinTagSizeInBytes = 10;

}  // namespace

StatusOr<HmacKey> HmacKeyManager::CreateKey(
    const HmacKeyFormat& hmac_key_format) const {
  HmacKey hmac_key;
  hmac_key.set_version(get_version());
  *(hmac_key.mutable_params()) = hmac_key_format.params();
  hmac_key.set_key_value(
      subtle::Random::GetRandomBytes(hmac_key_format.key_size()));
  return hmac_key;
}

StatusOr<HmacKey> HmacKeyManager::DeriveKey(
    const HmacKeyFormat& hmac_key_format, InputStream* input_stream) const {
  crypto::tink::util::Status status =
      ValidateVersion(hmac_key_format.version(), get_version());
  if (!status.ok()) return status;

  crypto::tink::util::StatusOr<std::string> randomness =
      ReadBytesFromStream(hmac_key_format.key_size(), input_stream);
  if (!randomness.ok()) {
    if (randomness.status().code() == absl::StatusCode::kOutOfRange) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not get enough pseudorandomness from input stream");
    }
    return randomness.status();
  }

  HmacKey hmac_key;
  hmac_key.set_version(get_version());
  *(hmac_key.mutable_params()) = hmac_key_format.params();
  hmac_key.set_key_value(randomness.ValueOrDie());
  return hmac_key;
}

Status HmacKeyManager::ValidateParams(const HmacParams& params) const {
  if (params.tag_size() < kMinTagSizeInBytes) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid HmacParams: tag_size %d is too small.",
                     params.tag_size());
  }
  std::map<HashType, uint32_t> max_tag_size = {{HashType::SHA1, 20},
                                               {HashType::SHA224, 28},
                                               {HashType::SHA256, 32},
                                               {HashType::SHA384, 48},
                                               {HashType::SHA512, 64}};
  if (max_tag_size.find(params.hash()) == max_tag_size.end()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid HmacParams: HashType '%s' not supported.",
                     Enums::HashName(params.hash()));
  } else {
    if (params.tag_size() > max_tag_size[params.hash()]) {
      return ToStatusF(
          absl::StatusCode::kInvalidArgument,
          "Invalid HmacParams: tag_size %d is too big for HashType '%s'.",
          params.tag_size(), Enums::HashName(params.hash()));
    }
  }
  return util::OkStatus();
}

Status HmacKeyManager::ValidateKey(const HmacKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().size() < kMinKeySizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HmacKey: key_value is too short.");
  }
  return ValidateParams(key.params());
}

// static
Status HmacKeyManager::ValidateKeyFormat(
    const HmacKeyFormat& key_format) const {
  if (key_format.key_size() < kMinKeySizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HmacKeyFormat: key_size is too small.");
  }
  return ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
