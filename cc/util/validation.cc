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

#include "tink/util/validation.h"

#include "absl/status/status.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"

using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

namespace crypto {
namespace tink {

util::Status ValidateAesKeySize(uint32_t key_size) {
  if (key_size != 16 && key_size != 32) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "AES key has %d bytes; supported sizes: 16 or 32 bytes.",
                     key_size);
  }
  return util::OkStatus();
}

util::Status ValidateKey(const Keyset::Key& key) {
  if (!key.has_key_data()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "key %d, has no key data", key.key_id());
  }

  if (key.output_prefix_type() ==
      google::crypto::tink::OutputPrefixType::UNKNOWN_PREFIX) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "key %d has unknown prefix", key.key_id());
  }

  if (key.status() == google::crypto::tink::KeyStatusType::UNKNOWN_STATUS) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "key %d has unknown status", key.key_id());
  }
  return util::OkStatus();
}

util::Status ValidateKeyset(const Keyset& keyset) {
  if (keyset.key_size() < 1) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "A valid keyset must contain at least one key.");
  }

  uint32_t primary_key_id = keyset.primary_key_id();
  bool has_primary_key = false;
  bool contains_only_public_key_material = true;
  int enabled_keys = 0;

  for (int i = 0; i < keyset.key_size(); i++) {
    const Keyset::Key& key = keyset.key(i);


    if (key.status() != KeyStatusType::ENABLED) {
      continue;
    }
    enabled_keys += 1;

    auto validation_result = ValidateKey(key);
    if (!validation_result.ok()) {
      return validation_result;
    }

    if (key.status() == KeyStatusType::ENABLED &&
        key.key_id() == primary_key_id) {
      if (has_primary_key) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "keyset contains multiple primary keys");
      }
      has_primary_key = true;
    }

    if (key.key_data().key_material_type() != KeyData::ASYMMETRIC_PUBLIC) {
      contains_only_public_key_material = false;
    }
  }

  if (enabled_keys == 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "keyset must contain at least one ENABLED key");
  }

  // A public key can be used for verification without being set as the primary
  // key. Therefore, it is okay to have a keyset that contains public but
  // doesn't have a primary key set.
  if (!has_primary_key && !contains_only_public_key_material) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "keyset doesn't contain a valid primary key");
  }

  return util::OkStatus();
}

util::Status ValidateVersion(uint32_t candidate, uint32_t max_expected) {
  if (candidate > max_expected) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Key has version '%d'; "
                     "only keys with version in range [0..%d] are supported.",
                     candidate, max_expected);
  }
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
