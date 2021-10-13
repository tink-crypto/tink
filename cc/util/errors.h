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

#ifndef TINK_UTIL_ERRORS_H_
#define TINK_UTIL_ERRORS_H_

#include "absl/strings/str_format.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

// Constructs a Status with formatted error message.
template <typename... Args>
ABSL_DEPRECATED("Prefer using absl::StatusCode as a first argument.")
util::Status ToStatusF(util::error::Code code,
                       const absl::FormatSpec<Args...>& format,
                       const Args&... args) {
  return util::Status(code, absl::StrFormat(format, args...));
}

// Constructs a Status with formatted error message using absl::StatusCode.
template <typename... Args>
util::Status ToStatusF(absl::StatusCode code,
                       const absl::FormatSpec<Args...>& format,
                       const Args&... args) {
  return util::Status(code, absl::StrFormat(format, args...));
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_ERRORS_H_
