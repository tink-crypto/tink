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

#ifndef TINK_PUBLIC_KEY_SIGN_H_
#define TINK_PUBLIC_KEY_SIGN_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Interface for public key signing.
// Digital Signatures provide functionality of signing data and verification of
// the signatures. They are represented by a pair of primitives (interfaces)
// 'PublicKeySign' for signing of data, and 'PublicKeyVerify' for verification
// of signatures. Implementations of these interfaces are secure against
// adaptive chosen-message attacks. Signing data ensures the authenticity and
// the integrity of that data, but not its secrecy.
class PublicKeySign {
 public:
  // Computes the signature for 'data'.
  virtual crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const = 0;

  virtual ~PublicKeySign() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PUBLIC_KEY_SIGN_H_
