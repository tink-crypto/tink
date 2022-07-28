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
#ifndef TINK_SIGNATURE_FAILING_SIGNATURE_H_
#define TINK_SIGNATURE_FAILING_SIGNATURE_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"

namespace crypto {
namespace tink {

// Returns a PublicKeySign that always return an error when calling Sign.
// The error message will contain `message`.
std::unique_ptr<PublicKeySign> CreateAlwaysFailingPublicKeySign(
    std::string message = "");

// Returns a PublicKeyVerify that always returns an error when calling Verify.
// The error message will contain `message`.
std::unique_ptr<PublicKeyVerify> CreateAlwaysFailingPublicKeyVerify(
    std::string message = "");

}  // namespace tink
}  // namespace crypto


#endif  // TINK_SIGNATURE_FAILING_SIGNATURE_H_
