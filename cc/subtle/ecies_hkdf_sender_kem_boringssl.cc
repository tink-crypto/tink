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

#include "tink/subtle/ecies_hkdf_sender_kem_boringssl.h"

#include "absl/memory/memory.h"
#include "openssl/bn.h"
#include "openssl/curve25519.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/subtle_util_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {

EciesHkdfSenderKemBoringSsl::KemKey::KemKey(const std::string& kem_bytes,
                                            const std::string& symmetric_key)
    : kem_bytes_(kem_bytes), symmetric_key_(symmetric_key) {}

const std::string&
EciesHkdfSenderKemBoringSsl::KemKey::KemKey::get_kem_bytes() const {
  return kem_bytes_;
}

const std::string&
EciesHkdfSenderKemBoringSsl::KemKey::KemKey::get_symmetric_key() const {
  return symmetric_key_;
}

// static
util::StatusOr<std::unique_ptr<const EciesHkdfSenderKemBoringSsl>>
EciesHkdfSenderKemBoringSsl::New(subtle::EllipticCurveType curve,
                                 const std::string& pubx,
                                 const std::string& puby) {
  switch (curve) {
    case EllipticCurveType::NIST_P256:
    case EllipticCurveType::NIST_P384:
    case EllipticCurveType::NIST_P521:
      return EciesHkdfNistPCurveSendKemBoringSsl::New(curve, pubx, puby);
    case EllipticCurveType::CURVE25519:
      return EciesHkdfX25519SendKemBoringSsl::New(curve, pubx, puby);
    default:
      return util::Status(util::error::UNIMPLEMENTED,
                          "Unsupported elliptic curve");
  }
}

EciesHkdfNistPCurveSendKemBoringSsl::EciesHkdfNistPCurveSendKemBoringSsl(
    subtle::EllipticCurveType curve, const std::string& pubx,
    const std::string& puby, EC_POINT* peer_pub_key)
    : curve_(curve), pubx_(pubx), puby_(puby), peer_pub_key_(peer_pub_key) {}

// static
util::StatusOr<std::unique_ptr<const EciesHkdfSenderKemBoringSsl>>
EciesHkdfNistPCurveSendKemBoringSsl::New(subtle::EllipticCurveType curve,
                                         const std::string& pubx,
                                         const std::string& puby) {
  auto status_or_ec_point =
      SubtleUtilBoringSSL::GetEcPoint(curve, pubx, puby);
  if (!status_or_ec_point.ok()) return status_or_ec_point.status();
  std::unique_ptr<const EciesHkdfSenderKemBoringSsl> sender_kem(
      new EciesHkdfNistPCurveSendKemBoringSsl(curve, pubx, puby,
                                              status_or_ec_point.ValueOrDie()));
  return std::move(sender_kem);
}

util::StatusOr<std::unique_ptr<const EciesHkdfSenderKemBoringSsl::KemKey>>
EciesHkdfNistPCurveSendKemBoringSsl::GenerateKey(
    subtle::HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    subtle::EcPointFormat point_format) const {
  if (peer_pub_key_.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "peer_pub_key_ wasn't initialized");
  }

  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve_);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  bssl::UniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
  bssl::UniquePtr<EC_KEY> ephemeral_key(EC_KEY_new());
  if (1 != EC_KEY_set_group(ephemeral_key.get(), group.get())) {
    return util::Status(util::error::INTERNAL, "EC_KEY_set_group failed");
  }
  if (1 != EC_KEY_generate_key(ephemeral_key.get())) {
    return util::Status(util::error::INTERNAL, "EC_KEY_generate_key failed");
  }
  const BIGNUM* ephemeral_priv = EC_KEY_get0_private_key(ephemeral_key.get());
  const EC_POINT* ephemeral_pub = EC_KEY_get0_public_key(ephemeral_key.get());
  auto status_or_string_kem =
      SubtleUtilBoringSSL::EcPointEncode(curve_, point_format, ephemeral_pub);
  if (!status_or_string_kem.ok()) {
    return status_or_string_kem.status();
  }
  std::string kem_bytes(status_or_string_kem.ValueOrDie());
  auto status_or_string_shared_secret =
      SubtleUtilBoringSSL::ComputeEcdhSharedSecret(curve_, ephemeral_priv,
                                                   peer_pub_key_.get());
  if (!status_or_string_shared_secret.ok()) {
    return status_or_string_shared_secret.status();
  }
  std::string shared_secret(status_or_string_shared_secret.ValueOrDie());
  auto status_or_string_symmetric_key = Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
  if (!status_or_string_symmetric_key.ok()) {
    return status_or_string_symmetric_key.status();
  }
  std::string symmetric_key(status_or_string_symmetric_key.ValueOrDie());
  auto kem_key = absl::make_unique<const KemKey>(kem_bytes, symmetric_key);
  return std::move(kem_key);
}

EciesHkdfX25519SendKemBoringSsl::EciesHkdfX25519SendKemBoringSsl(
    const std::string& peer_public_value) {
  peer_public_value.copy(reinterpret_cast<char*>(peer_public_value_),
                         X25519_PUBLIC_VALUE_LEN);
}

// static
util::StatusOr<std::unique_ptr<const EciesHkdfSenderKemBoringSsl>>
EciesHkdfX25519SendKemBoringSsl::New(subtle::EllipticCurveType curve,
                                     const std::string& pubx,
                                     const std::string& puby) {
  if (curve != CURVE25519) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "curve is not CURVE25519");
  }
  if (pubx.size() != X25519_PUBLIC_VALUE_LEN) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "pubx has unexpected length");
  }
  if (!puby.empty()) {
    return util::Status(util::error::INVALID_ARGUMENT, "puby is not empty");
  }
  std::unique_ptr<const EciesHkdfSenderKemBoringSsl> sender_kem(
      new EciesHkdfX25519SendKemBoringSsl(pubx));
  return std::move(sender_kem);
}

util::StatusOr<std::unique_ptr<const EciesHkdfSenderKemBoringSsl::KemKey>>
EciesHkdfX25519SendKemBoringSsl::GenerateKey(
    subtle::HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    subtle::EcPointFormat point_format) const {
  if (point_format != EcPointFormat::COMPRESSED) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "X25519 only supports compressed elliptic curve points");
  }

  uint8_t ephemeral_private_key[X25519_PRIVATE_KEY_LEN];
  uint8_t ephemeral_public_value[X25519_PUBLIC_VALUE_LEN];
  X25519_keypair(ephemeral_public_value, ephemeral_private_key);
  std::string kem_bytes(ephemeral_public_value,
                        &ephemeral_public_value[X25519_PUBLIC_VALUE_LEN]);

  uint8_t shared_key[X25519_SHARED_KEY_LEN];
  X25519(shared_key, ephemeral_private_key, peer_public_value_);
  std::string shared_secret(shared_key, &shared_key[X25519_SHARED_KEY_LEN]);

  auto status_or_string_symmetric_key = Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
  if (!status_or_string_symmetric_key.ok()) {
    return status_or_string_symmetric_key.status();
  }
  std::string symmetric_key(status_or_string_symmetric_key.ValueOrDie());
  auto kem_key = absl::make_unique<const KemKey>(kem_bytes, symmetric_key);
  return std::move(kem_key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
