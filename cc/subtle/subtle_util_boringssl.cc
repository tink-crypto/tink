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

#include "tink/subtle/subtle_util_boringssl.h"

#include <algorithm>
#include <iterator>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"
#include "absl/types/span.h"
#include "openssl/base.h"
#include "openssl/bn.h"
#include "openssl/cipher.h"
#include "openssl/curve25519.h"
#include "openssl/digest.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/mem.h"
#include "openssl/rsa.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

size_t FieldElementSizeInBytes(const EC_GROUP *group) {
  unsigned degree_bits = EC_GROUP_get_degree(group);
  return (degree_bits + 7) / 8;
}

}  // namespace

// static
std::unique_ptr<SubtleUtilBoringSSL::Ed25519Key>
SubtleUtilBoringSSL::GetNewEd25519Key() {
  // Generate a new secret seed.
  util::SecretData secret_seed = util::SecretDataFromStringView(
      crypto::tink::subtle::Random::GetRandomBytes(32));
  return GetNewEd25519KeyFromSeed(secret_seed);
}

// static
std::unique_ptr<SubtleUtilBoringSSL::Ed25519Key>
SubtleUtilBoringSSL::GetNewEd25519KeyFromSeed(
    const util::SecretData &secret_seed) {
  // Generate a new key pair.
  uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t out_private_key[ED25519_PRIVATE_KEY_LEN];

  ED25519_keypair_from_seed(out_public_key, out_private_key,
                            secret_seed.data());

  auto key = absl::make_unique<Ed25519Key>();
  key->public_key = std::string(reinterpret_cast<const char *>(out_public_key),
                                ED25519_PUBLIC_KEY_LEN);
  std::string tmp = std::string(reinterpret_cast<const char *>(out_private_key),
                                ED25519_PRIVATE_KEY_LEN);
  // ED25519_keypair appends the public key at the end of the private key. Keep
  // the first 32 bytes that contain the private key and discard the public key.
  key->private_key = tmp.substr(0, 32);
  return key;
}

// static
util::StatusOr<util::SecretData> SubtleUtilBoringSSL::ComputeEcdhSharedSecret(
    EllipticCurveType curve, const BIGNUM *priv_key, const EC_POINT *pub_key) {
  util::StatusOr<internal::SslUniquePtr<EC_GROUP>> priv_group =
      internal::EcGroupFromCurveType(curve);
  if (!priv_group.ok()) {
    return priv_group.status();
  }
  internal::SslUniquePtr<EC_POINT> shared_point(
      EC_POINT_new(priv_group->get()));
  // BoringSSL's EC_POINT_set_affine_coordinates_GFp documentation says that
  // "unlike with OpenSSL, it's considered an error if the point is not on the
  // curve". To be sure, we double check here.
  if (1 != EC_POINT_is_on_curve(priv_group->get(), pub_key, nullptr)) {
    return util::Status(absl::StatusCode::kInternal, "Point is not on curve");
  }
  // Compute the shared point.
  if (1 != EC_POINT_mul(priv_group->get(), shared_point.get(), nullptr, pub_key,
                        priv_key, nullptr)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Point multiplication failed");
  }
  // Check for buggy computation.
  if (1 !=
      EC_POINT_is_on_curve(priv_group->get(), shared_point.get(), nullptr)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Shared point is not on curve");
  }
  // Get shared point's x coordinate.
  internal::SslUniquePtr<BIGNUM> shared_x(BN_new());
  if (1 !=
      EC_POINT_get_affine_coordinates_GFp(priv_group->get(), shared_point.get(),
                                          shared_x.get(), nullptr, nullptr)) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }
  return internal::BignumToSecretData(
      shared_x.get(), FieldElementSizeInBytes(priv_group->get()));
}

// static
util::StatusOr<std::string> SubtleUtilBoringSSL::EcSignatureIeeeToDer(
    const EC_GROUP *group, absl::string_view ieee_sig) {
  size_t field_size_in_bytes = (EC_GROUP_get_degree(group) + 7) / 8;
  if (ieee_sig.size() != field_size_in_bytes * 2) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Signature is not valid.");
  }
  internal::SslUniquePtr<ECDSA_SIG> ecdsa(ECDSA_SIG_new());
  auto status_or_r =
      internal::StringToBignum(ieee_sig.substr(0, ieee_sig.size() / 2));
  if (!status_or_r.ok()) {
    return status_or_r.status();
  }
  auto status_or_s = internal::StringToBignum(
      ieee_sig.substr(ieee_sig.size() / 2, ieee_sig.size() / 2));
  if (!status_or_s.ok()) {
    return status_or_s.status();
  }
  if (1 != ECDSA_SIG_set0(ecdsa.get(), status_or_r.ValueOrDie().get(),
                          status_or_s.ValueOrDie().get())) {
    return util::Status(absl::StatusCode::kInternal, "ECDSA_SIG_set0 error.");
  }
  // ECDSA_SIG_set0 takes ownership of s and r's pointers.
  status_or_r.ValueOrDie().release();
  status_or_s.ValueOrDie().release();
  uint8_t *der = nullptr;
  size_t der_len;
  if (!ECDSA_SIG_to_bytes(&der, &der_len, ecdsa.get())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ECDSA_SIG_to_bytes error");
  }
  std::string result = std::string(reinterpret_cast<char *>(der), der_len);
  OPENSSL_free(der);
  return result;
}

const EVP_CIPHER *SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(
    uint32_t size_in_bytes) {
  util::StatusOr<const EVP_CIPHER *> res =
      internal::GetAesCtrCipherForKeySize(size_in_bytes);
  if (!res.ok()) {
    return nullptr;
  }
  return *res;
}

const EVP_CIPHER *SubtleUtilBoringSSL::GetAesGcmCipherForKeySize(
    uint32_t size_in_bytes) {
  util::StatusOr<const EVP_CIPHER *> res =
      internal::GetAesGcmCipherForKeySize(size_in_bytes);
  if (!res.ok()) {
    return nullptr;
  }
  return *res;
}

#ifdef OPENSSL_IS_BORINGSSL
const EVP_AEAD *SubtleUtilBoringSSL::GetAesGcmAeadForKeySize(
    uint32_t size_in_bytes) {
  util::StatusOr<const EVP_AEAD *> res =
      internal::GetAesGcmAeadForKeySize(size_in_bytes);
  if (!res.ok()) {
    return nullptr;
  }
  return *res;
}
#endif

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
