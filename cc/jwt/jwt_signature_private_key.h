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

#ifndef TINK_JWT_JWT_SIGNATURE_PRIVATE_KEY_H_
#define TINK_JWT_JWT_SIGNATURE_PRIVATE_KEY_H_

#include <string>

#include "absl/types/optional.h"
#include "tink/jwt/jwt_signature_parameters.h"
#include "tink/jwt/jwt_signature_public_key.h"
#include "tink/key.h"
#include "tink/private_key.h"

namespace crypto {
namespace tink {

// Represents the signing function for a JWT Signature primitive.
class JwtSignaturePrivateKey : public PrivateKey {
 public:
  const JwtSignaturePublicKey& GetPublicKey() const override = 0;

  absl::optional<std::string> GetKid() const {
    return GetPublicKey().GetKid();
  }

  absl::optional<int> GetIdRequirement() const override {
    return GetPublicKey().GetIdRequirement();
  }

  const JwtSignatureParameters& GetParameters() const override {
    return GetPublicKey().GetParameters();
  }

  bool operator==(const Key& other) const override = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_SIGNATURE_PRIVATE_KEY_H_
