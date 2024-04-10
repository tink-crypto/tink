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

#ifndef TINK_JWT_JWT_HMAC_PARAMETERS_H_
#define TINK_JWT_JWT_HMAC_PARAMETERS_H_

#include "tink/jwt/jwt_mac_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `JwtHmacKey`.
class JwtHmacParameters : public JwtMacParameters {
 public:
  // Strategy for handling the "kid" header.
  enum class KidStrategy : int {
    // The `kid` is the URL safe (RFC 4648 Section 5) base64-encoded big-endian
    // `key_id` in the keyset.
    //
    // In `ComputeMacAndEncode()`, Tink always adds the `kid`.
    //
    // In `VerifyMacAndDecode()`, Tink checks that the `kid` is present and
    // equal to this value.
    //
    // NOTE: This strategy is recommended by Tink.
    kBase64EncodedKeyId = 1,
    // The `kid` header is ignored.
    //
    // In `ComputeMacAndEncode()`, Tink does not write a `kid` header.
    //
    // In `VerifyMacAndDecode()`, Tink ignores the `kid` header.
    kIgnored = 2,
    // The `kid` is fixed. It can be obtained by calling `key.GetKid()`.
    //
    // In `ComputeMacAndEncode()`, Tink writes the `kid` header to the
    // value given by `key.getCustomKid()`.
    //
    // In `VerifyMacAndDecode()`, if the `kid` is present, it must match
    // `key.GetKid()`. If the `kid` is absent, it will be accepted.
    //
    // NOTE: Tink does not allow random generation of `JwtHmacKey` objects from
    // parameters objects with `KidStrategy::kCustom`.
    kCustom = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // MAC computation algorithm.
  enum class Algorithm : int {
    kHs256 = 1,
    kHs384 = 2,
    kHs512 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  JwtHmacParameters(const JwtHmacParameters& other) = default;
  JwtHmacParameters& operator=(const JwtHmacParameters& other) = default;
  JwtHmacParameters(JwtHmacParameters&& other) = default;
  JwtHmacParameters& operator=(JwtHmacParameters&& other) = default;

  // Creates JWT HMAC parameters object. Returns an error status if
  // `key_size_in_bytes` is less than 16 bytes, if `kid_strategy` is invalid, or
  // if `algorithm` is invalid.
  static util::StatusOr<JwtHmacParameters> Create(int key_size_in_bytes,
                                                  KidStrategy kid_strategy,
                                                  Algorithm algorithm);

  int KeySizeInBytes() const { return key_size_in_bytes_; }

  KidStrategy GetKidStrategy() const { return kid_strategy_; }

  Algorithm GetAlgorithm() const { return algorithm_; }

  bool AllowKidAbsent() const override {
    return kid_strategy_ == KidStrategy::kCustom ||
           kid_strategy_ == KidStrategy::kIgnored;
  }

  bool HasIdRequirement() const override {
    return kid_strategy_ == KidStrategy::kBase64EncodedKeyId;
  }

  bool operator==(const Parameters& other) const override;

 private:
  JwtHmacParameters(int key_size_in_bytes, KidStrategy kid_strategy,
                    Algorithm algorithm)
      : key_size_in_bytes_(key_size_in_bytes),
        kid_strategy_(kid_strategy),
        algorithm_(algorithm) {}

  int key_size_in_bytes_;
  KidStrategy kid_strategy_;
  Algorithm algorithm_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_HMAC_PARAMETERS_H_
