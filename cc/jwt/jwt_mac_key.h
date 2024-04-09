// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_JWT_JWT_MAC_KEY_H_
#define TINK_JWT_JWT_MAC_KEY_H_

#include <string>

#include "absl/types/optional.h"
#include "tink/jwt/jwt_mac_parameters.h"
#include "tink/key.h"

namespace crypto {
namespace tink {

// Represents the authentication and verification functions for the JWT MAC
// primitive.
class JwtMacKey : public Key {
 public:
  // Returns the `kid` to be used for this key
  // (https://www.rfc-editor.org/rfc/rfc7517#section-4.5).
  //
  // Note that the `kid` is not necessarily related to Tink's key ID in the
  // keyset.
  //
  // If present, this `kid` will be written into the `kid` header during
  // `ComputeMacAndEncode()`. If absent, no `kid` will be written.
  //
  // If present, and the `kid` header is present, the contents of the
  // `kid` header need to match the return value of this function for
  // validation to succeed in `VerifyMacAndDecode()`.
  //
  // Note that `GetParameters().AllowKidAbsent()` specifies whether or not
  // omitting the `kid` header is allowed. Of course, if
  // `GetParameters().AllowKidAbsent()` returns false, then `GetKid()` must
  // return a non-empty value.
  virtual absl::optional<std::string> GetKid() const = 0;

  const JwtMacParameters& GetParameters() const override = 0;

  bool operator==(const Key& other) const override = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_MAC_KEY_H_
