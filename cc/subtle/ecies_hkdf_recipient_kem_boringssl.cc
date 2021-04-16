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

#include "tink/subtle/ecies_hkdf_recipient_kem_boringssl.h"

#include "absl/memory/memory.h"
#include "openssl/bn.h"
#include "openssl/curve25519.h"
#include "openssl/ec.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
EciesHkdfRecipientKemBoringSsl::New(EllipticCurveType curve,
                                    util::SecretData priv_key) {
  switch (curve) {
    case EllipticCurveType::NIST_P256:
    case EllipticCurveType::NIST_P384:
    case EllipticCurveType::NIST_P521:
      return EciesHkdfNistPCurveRecipientKemBoringSsl::New(curve,
                                                           std::move(priv_key));
    case EllipticCurveType::CURVE25519:
      return EciesHkdfX25519RecipientKemBoringSsl::New(curve,
                                                       std::move(priv_key));
    default:
      return util::Status(util::error::UNIMPLEMENTED,
                          "Unsupported elliptic curve");
  }
}

// static
util::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
EciesHkdfNistPCurveRecipientKemBoringSsl::New(EllipticCurveType curve,
                                              util::SecretData priv_key) {
  auto status = internal::CheckFipsCompatibility<
      EciesHkdfNistPCurveRecipientKemBoringSsl>();
  if (!status.ok()) return status;

  if (priv_key.empty()) {
    return util::Status(util::error::INVALID_ARGUMENT, "empty priv_key");
  }
  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve);
  if (!status_or_ec_group.ok()) return status_or_ec_group.status();
  // TODO(przydatek): consider refactoring SubtleUtilBoringSSL,
  //     so that the saved group can be used for KEM operations.
  return {absl::WrapUnique(new EciesHkdfNistPCurveRecipientKemBoringSsl(
      curve, std::move(priv_key), status_or_ec_group.ValueOrDie()))};
}

EciesHkdfNistPCurveRecipientKemBoringSsl::
    EciesHkdfNistPCurveRecipientKemBoringSsl(EllipticCurveType curve,
                                             util::SecretData priv_key_value,
                                             EC_GROUP* ec_group)
    : curve_(curve),
      priv_key_value_(std::move(priv_key_value)),
      ec_group_(ec_group) {}

util::StatusOr<util::SecretData>
EciesHkdfNistPCurveRecipientKemBoringSsl::GenerateKey(
    absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    EcPointFormat point_format) const {
  auto status_or_ec_point =
      SubtleUtilBoringSSL::EcPointDecode(curve_, point_format, kem_bytes);
  if (!status_or_ec_point.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT, "Invalid KEM bytes: %s",
                     status_or_ec_point.status().error_message());
  }
  bssl::UniquePtr<EC_POINT> pub_key =
      std::move(status_or_ec_point.ValueOrDie());
  bssl::UniquePtr<BIGNUM> priv_key(
      BN_bin2bn(priv_key_value_.data(), priv_key_value_.size(), nullptr));
  auto shared_secret_or = SubtleUtilBoringSSL::ComputeEcdhSharedSecret(
      curve_, priv_key.get(), pub_key.get());
  if (!shared_secret_or.ok()) {
    return shared_secret_or.status();
  }
  util::SecretData shared_secret = shared_secret_or.ValueOrDie();
  return Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
}

EciesHkdfX25519RecipientKemBoringSsl::EciesHkdfX25519RecipientKemBoringSsl(
    util::SecretData private_key)
    : private_key_(std::move(private_key)) {}

// static
util::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
EciesHkdfX25519RecipientKemBoringSsl::New(EllipticCurveType curve,
                                          util::SecretData priv_key) {
  auto status =
      internal::CheckFipsCompatibility<EciesHkdfX25519RecipientKemBoringSsl>();
  if (!status.ok()) return status;

  if (curve != CURVE25519) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "curve is not CURVE25519");
  }
  if (priv_key.size() != X25519_PUBLIC_VALUE_LEN) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "pubx has unexpected length");
  }

  return {absl::WrapUnique(
      new EciesHkdfX25519RecipientKemBoringSsl(std::move(priv_key)))};
}

crypto::tink::util::StatusOr<util::SecretData>
EciesHkdfX25519RecipientKemBoringSsl::GenerateKey(
    absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    EcPointFormat point_format) const {
  if (point_format != EcPointFormat::COMPRESSED) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "X25519 only supports compressed elliptic curve points");
  }

  if (kem_bytes.size() != X25519_PUBLIC_VALUE_LEN) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "kem_bytes has unexpected size");
  }

  util::SecretData shared_secret(X25519_SHARED_KEY_LEN);
  X25519(shared_secret.data(), private_key_.data(),
         reinterpret_cast<const uint8_t*>(kem_bytes.data()));

  return Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
