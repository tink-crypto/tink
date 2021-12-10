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
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::subtle::EllipticCurveType;

util::StatusOr<std::unique_ptr<X25519Key>> NewX25519Key() {
  auto key = absl::make_unique<X25519Key>();
  EVP_PKEY* private_key = nullptr;
  SslUniquePtr<EVP_PKEY_CTX> pctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, /*e=*/nullptr));
  if (EVP_PKEY_keygen_init(pctx.get()) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_keygen_init failed");
  }
  if (EVP_PKEY_keygen(pctx.get(), &private_key) != 1) {
    return util::Status(absl::StatusCode::kInternal, "EVP_PKEY_keygen failed");
  }
  SslUniquePtr<EVP_PKEY> private_key_ptr(private_key);

  size_t len = X25519KeyPrivKeySize();
  if (EVP_PKEY_get_raw_private_key(private_key_ptr.get(), key->private_key,
                                   &len) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_get_raw_private_key failed");
  }
  len = X25519KeyPubKeySize();
  if (EVP_PKEY_get_raw_public_key(private_key_ptr.get(), key->public_value,
                                  &len) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_get_raw_public_key failed");
  }
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

util::StatusOr<SslUniquePtr<EC_GROUP>> EcGroupFromCurveType(
    EllipticCurveType curve_type) {
  EC_GROUP* ec_group = nullptr;
  switch (curve_type) {
    case EllipticCurveType::NIST_P256: {
      ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      break;
    }
    case EllipticCurveType::NIST_P384: {
      ec_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
      break;
    }
    case EllipticCurveType::NIST_P521: {
      ec_group = EC_GROUP_new_by_curve_name(NID_secp521r1);
      break;
    }
    default:
      return util::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
  if (ec_group == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_GROUP_new_by_curve_name failed");
  }
  return {SslUniquePtr<EC_GROUP>(ec_group)};
}

util::StatusOr<EllipticCurveType> CurveTypeFromEcGroup(const EC_GROUP* group) {
  if (group == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Null group provided");
  }
  switch (EC_GROUP_get_curve_name(group)) {
    case NID_X9_62_prime256v1:
      return EllipticCurveType::NIST_P256;
    case NID_secp384r1:
      return EllipticCurveType::NIST_P384;
    case NID_secp521r1:
      return EllipticCurveType::NIST_P521;
    default:
      return util::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
