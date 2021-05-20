// Copyright 2021 Google LLC
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

#ifndef TINK_JWT_JWT_PUBLIC_KEY_SIGN_H_
#define TINK_JWT_JWT_PUBLIC_KEY_SIGN_H_

#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/jwt/raw_jwt.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Interface for signing JWT.
//
// Sees RFC 7519 and RFC 7515. Security guarantees: similar to PublicKeySign.
class JwtPublicKeySign {
 public:
  // Computes a signature, and encodes the JWT and the signature in the JWS
  // compact serialization format.
  virtual crypto::tink::util::StatusOr<std::string> SignAndEncode(
      const RawJwt& token) const = 0;

  virtual ~JwtPublicKeySign() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_PUBLIC_KEY_SIGN_H_
