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
#include "absl/status/status.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/util/errors.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// Generates a shared secret using `private_key` and `peer_public_key`.
util::StatusOr<util::SecretData> X25519SharedSecret(
    EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {

  internal::SslUniquePtr<EVP_PKEY_CTX> pctx(
      EVP_PKEY_CTX_new(private_key, nullptr));
  util::SecretData shared_secret(internal::X25519KeySharedKeySize());
  size_t out_key_length = shared_secret.size();
  if (EVP_PKEY_derive_init(pctx.get()) <= 0 ||
      EVP_PKEY_derive_set_peer(pctx.get(), peer_public_key) <= 0 ||
      EVP_PKEY_derive(pctx.get(), shared_secret.data(), &out_key_length) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "Secret generation failed");
  }
  return shared_secret;
}

}  // namespace

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
      return util::Status(absl::StatusCode::kUnimplemented,
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
    return util::Status(absl::StatusCode::kInvalidArgument, "empty priv_key");
  }
  auto status_or_ec_group = internal::EcGroupFromCurveType(curve);
  if (!status_or_ec_group.ok()) return status_or_ec_group.status();
  // TODO(przydatek): consider refactoring internal/ec_util,
  //     so that the saved group can be used for KEM operations.
  return {absl::WrapUnique(new EciesHkdfNistPCurveRecipientKemBoringSsl(
      curve, std::move(priv_key), std::move(status_or_ec_group.ValueOrDie())))};
}

EciesHkdfNistPCurveRecipientKemBoringSsl::
    EciesHkdfNistPCurveRecipientKemBoringSsl(
        EllipticCurveType curve, util::SecretData priv_key_value,
        internal::SslUniquePtr<EC_GROUP> ec_group)
    : curve_(curve),
      priv_key_value_(std::move(priv_key_value)),
      ec_group_(std::move(ec_group)) {}

util::StatusOr<util::SecretData>
EciesHkdfNistPCurveRecipientKemBoringSsl::GenerateKey(
    absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    EcPointFormat point_format) const {
  auto status_or_ec_point =
      internal::EcPointDecode(curve_, point_format, kem_bytes);
  if (!status_or_ec_point.ok()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid KEM bytes: %s",
                     status_or_ec_point.status().message());
  }
  internal::SslUniquePtr<EC_POINT> pub_key =
      std::move(status_or_ec_point.ValueOrDie());
  internal::SslUniquePtr<BIGNUM> priv_key(
      BN_bin2bn(priv_key_value_.data(), priv_key_value_.size(), nullptr));
  auto shared_secret_or =
      internal::ComputeEcdhSharedSecret(curve_, priv_key.get(), pub_key.get());
  if (!shared_secret_or.ok()) {
    return shared_secret_or.status();
  }
  util::SecretData shared_secret = shared_secret_or.ValueOrDie();
  return Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
}

EciesHkdfX25519RecipientKemBoringSsl::EciesHkdfX25519RecipientKemBoringSsl(
    internal::SslUniquePtr<EVP_PKEY> private_key)
    : private_key_(std::move(private_key)) {}

// static
util::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
EciesHkdfX25519RecipientKemBoringSsl::New(EllipticCurveType curve,
                                          util::SecretData priv_key) {
  auto status =
      internal::CheckFipsCompatibility<EciesHkdfX25519RecipientKemBoringSsl>();
  if (!status.ok()) return status;

  if (curve != CURVE25519) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "curve is not CURVE25519");
  }
  if (priv_key.size() != internal::X25519KeyPubKeySize()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "pubx has unexpected length");
  }

  internal::SslUniquePtr<EVP_PKEY> ssl_priv_key(EVP_PKEY_new_raw_private_key(
      /*type=*/EVP_PKEY_X25519, /*unused=*/nullptr, /*in=*/priv_key.data(),
      /*len=*/internal::Ed25519KeyPrivKeySize()));
  if (ssl_priv_key == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_new_raw_private_key failed");
  }

  return {absl::WrapUnique(
      new EciesHkdfX25519RecipientKemBoringSsl(std::move(ssl_priv_key)))};
}

crypto::tink::util::StatusOr<util::SecretData>
EciesHkdfX25519RecipientKemBoringSsl::GenerateKey(
    absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    EcPointFormat point_format) const {
  if (point_format != EcPointFormat::COMPRESSED) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "X25519 only supports compressed elliptic curve points");
  }

  if (kem_bytes.size() != internal::X25519KeyPubKeySize()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "kem_bytes has unexpected size");
  }

  internal::SslUniquePtr<EVP_PKEY> peer_key(EVP_PKEY_new_raw_public_key(
      /*type=*/EVP_PKEY_X25519, /*unused=*/nullptr,
      /*in=*/reinterpret_cast<const uint8_t*>(kem_bytes.data()),
      /*len=*/internal::Ed25519KeyPubKeySize()));
  if (peer_key == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_new_raw_public_key failed");
  }

  util::StatusOr<util::SecretData> shared_secret =
      X25519SharedSecret(private_key_.get(), peer_key.get());
  if (!shared_secret.ok()) {
    return shared_secret.status();
  }

  return Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, *shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
