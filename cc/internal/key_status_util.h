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

#ifndef TINK_INTERNAL_KEY_STATUS_UTIL_H_
#define TINK_INTERNAL_KEY_STATUS_UTIL_H_

#include <string>

#include "tink/key_status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns `KeyStatus` C++ enum for a given `KeyStatusType` proto enum. If
// `status_type` is unrecognized (i.e., not handled), then an error is returned.
util::StatusOr<KeyStatus> FromKeyStatusType(
    google::crypto::tink::KeyStatusType status_type);

// Returns `KeyStatusType` proto enum for a given `KeyStatus` C++ enum. If
// `status` is unrecognized (i.e., not handled), then an error is returned.
util::StatusOr<google::crypto::tink::KeyStatusType> ToKeyStatusType(
    KeyStatus status);

// Returns a canonical name for a `KeyStatus` based on the corresponding
// `KeyStatusType` proto enum.
std::string ToKeyStatusName(KeyStatus status);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_STATUS_UTIL_H_
