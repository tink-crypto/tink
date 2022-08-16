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
#ifndef TINK_HYBRID_FAILING_HYBRID_H_
#define TINK_HYBRID_FAILING_HYBRID_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"

namespace crypto {
namespace tink {

// Returns a HybridEncrypt that always returns an error when calling Encrypt.
// The error message will contain `message`.
std::unique_ptr<HybridEncrypt> CreateAlwaysFailingHybridEncrypt(
    std::string message = "");

// Returns a HybridDecrypt that always returns an error when calling Decrypt.
// The error message will contain `message`.
std::unique_ptr<HybridDecrypt> CreateAlwaysFailingHybridDecrypt(
    std::string message = "");

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_FAILING_HYBRID_H_
