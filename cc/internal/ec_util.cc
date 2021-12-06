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
#include "tink/internal/ec_util.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/curve25519.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

std::unique_ptr<X25519Key> NewX25519Key() {
  auto key = absl::make_unique<X25519Key>();
  X25519_keypair(key->public_value, key->private_key);
  return key;
}

EcKey EcKeyFromX25519Key(const X25519Key* x25519_key) {
  EcKey ec_key;
  ec_key.curve = subtle::EllipticCurveType::CURVE25519;
  // Curve25519 public key is x, not (x,y).
  ec_key.pub_x =
      std::string(reinterpret_cast<const char*>(x25519_key->public_value),
                  X25519KeyPubKeySize());
  ec_key.priv = util::SecretData(std::begin(x25519_key->private_key),
                                 std::end(x25519_key->private_key));
  return ec_key;
}

util::StatusOr<std::unique_ptr<X25519Key>> X25519KeyFromEcKey(
    const EcKey& ec_key) {
  auto x25519_key = absl::make_unique<X25519Key>();
  if (ec_key.curve != subtle::EllipticCurveType::CURVE25519) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "This key is not on curve 25519");
  }
  if (!ec_key.pub_y.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid X25519 key. pub_y is unexpectedly set.");
  }
  // Curve25519 public key is x, not (x,y).
  std::copy_n(ec_key.pub_x.begin(), X25519KeyPubKeySize(),
              std::begin(x25519_key->public_value));
  std::copy_n(ec_key.priv.begin(), X25519KeyPrivKeySize(),
              std::begin(x25519_key->private_key));
  return std::move(x25519_key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
