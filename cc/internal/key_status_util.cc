// Copyright 2022 Google LLC
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

#include "tink/internal/key_status_util.h"

#include <string>

#include "absl/status/status.h"
#include "tink/key_status.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::KeyStatusType;

util::StatusOr<KeyStatus> FromKeyStatusType(KeyStatusType status_type) {
  switch (status_type) {
    case KeyStatusType::ENABLED:
      return KeyStatus::kEnabled;
    case KeyStatusType::DISABLED:
      return KeyStatus::kDisabled;
    case KeyStatusType::DESTROYED:
      return KeyStatus::kDestroyed;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid key status type.");
  }
}

util::StatusOr<KeyStatusType> ToKeyStatusType(KeyStatus status) {
  switch (status) {
    case KeyStatus::kEnabled:
      return KeyStatusType::ENABLED;
    case KeyStatus::kDisabled:
      return KeyStatusType::DISABLED;
    case KeyStatus::kDestroyed:
      return KeyStatusType::DESTROYED;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid key status.");
  }
}

std::string ToKeyStatusName(KeyStatus status) {
  switch (status) {
    case KeyStatus::kEnabled:
    return KeyStatusType_Name(KeyStatusType::ENABLED);
    case KeyStatus::kDisabled:
    return KeyStatusType_Name(KeyStatusType::DISABLED);
    case KeyStatus::kDestroyed:
      return KeyStatusType_Name(KeyStatusType::DESTROYED);
    default:
      return KeyStatusType_Name(KeyStatusType::UNKNOWN_STATUS);
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
