// Copyright 2022 Google LLC
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
#ifndef TINK_MAC_FAILING_MAC_H_
#define TINK_MAC_FAILING_MAC_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/mac.h"

namespace crypto {
namespace tink {

// Returns a MAC that always returns an error when calling ComputeMac or
// VerifyMac. The error message will contain `message`.
std::unique_ptr<Mac> CreateAlwaysFailingMac(std::string message = "");

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_FAILING_MAC_H_
