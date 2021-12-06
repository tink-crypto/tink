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
#ifndef TINK_INTERNAL_EC_UTIL_H_
#define TINK_INTERNAL_EC_UTIL_H_

#include <string>

#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr int64_t X25519KeyPubKeySize() { return 32; }
constexpr int64_t X25519KeyPrivKeySize() { return 32; }

struct EcKey {
  subtle::EllipticCurveType curve;
  // Affine coordinates in bigendian representation.
  std::string pub_x;
  std::string pub_y;
  // Big integer in bigendian representation.
  crypto::tink::util::SecretData priv;
};

struct X25519Key {
  uint8_t public_value[X25519KeyPubKeySize()];
  uint8_t private_key[X25519KeyPrivKeySize()];
};

struct Ed25519Key {
  std::string public_key;
  std::string private_key;
};

// Returns a new X25519Key key.
std::unique_ptr<X25519Key> NewX25519Key();

// Returns a X25519Key matching the specified EcKey.
crypto::tink::util::StatusOr<std::unique_ptr<X25519Key>> X25519KeyFromEcKey(
    const EcKey &ec_key);

// Returns an EcKey matching the specified X25519Key.
EcKey EcKeyFromX25519Key(const X25519Key *x25519_key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_EC_UTIL_H_
