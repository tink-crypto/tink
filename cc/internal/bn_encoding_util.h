// Copyright 2023 Google LLC
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
#ifndef TINK_INTERNAL_BN_ENCODING_UTIL_H_
#define TINK_INTERNAL_BN_ENCODING_UTIL_H_

#include <stddef.h>

#include <string>

#include "absl/strings/string_view.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns the value of a big integer `big_integer_encoding` (represented as a
// big endian encoded string), left padded to obtain a fixed length `length`.
// Returns an error if the `length` is too short.
crypto::tink::util::StatusOr<std::string> GetValueOfFixedLength(
    absl::string_view big_integer_encoding, int length);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_BN_ENCODING_UTIL_H_
