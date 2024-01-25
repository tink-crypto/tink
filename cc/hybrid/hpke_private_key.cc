// Copyright 2023 Google LLC
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

#include "tink/hybrid/hpke_private_key.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/internal/bn_util.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::StatusOr<subtle::EllipticCurveType> CurveTypeFromKemId(
    HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return subtle::EllipticCurveType::NIST_P256;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      return subtle::EllipticCurveType::NIST_P384;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      return subtle::EllipticCurveType::NIST_P521;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return subtle::EllipticCurveType::CURVE25519;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown KEM ID: ", kem_id));
  }
}

util::Status ValidatePrivateKeyLength(HpkeParameters::KemId kem_id,
                                      int length) {
  int expected_length;
  switch (kem_id) {
    // Key lengths from 'Nsk' column in
    // https://www.rfc-editor.org/rfc/rfc9180.html#table-2.
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      expected_length = 32;
      break;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      expected_length = 48;
      break;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      expected_length = 66;
      break;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      expected_length = 32;
      break;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown KEM ID: ", kem_id));
  }

  // Validate key length.
  if (expected_length != length) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat(
            "Invalid private key length for KEM %d (expected %d, got %d)",
            kem_id, expected_length, length));
  }

  return util::OkStatus();
}

bool IsNistKem(HpkeParameters::KemId kem_id) {
  return kem_id == HpkeParameters::KemId::kDhkemP256HkdfSha256 ||
         kem_id == HpkeParameters::KemId::kDhkemP384HkdfSha384 ||
         kem_id == HpkeParameters::KemId::kDhkemP521HkdfSha512;
}

util::Status ValidateNistEcKeyPair(subtle::EllipticCurveType curve,
                                   absl::string_view public_key_bytes,
                                   const util::SecretData& private_key_bytes) {
  // Construct EC_KEY from public and private key bytes.
  util::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group->get());

  util::StatusOr<internal::SslUniquePtr<EC_POINT>> public_key =
      internal::EcPointDecode(curve, subtle::EcPointFormat::UNCOMPRESSED,
                              public_key_bytes);
  if (!public_key.ok()) {
    return public_key.status();
  }

  if (!EC_KEY_set_public_key(key.get(), public_key->get())) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
  }

  util::StatusOr<internal::SslUniquePtr<BIGNUM>> priv_key =
      internal::StringToBignum(util::SecretDataAsStringView(private_key_bytes));
  if (!priv_key.ok()) {
    return priv_key.status();
  }
  if (!EC_KEY_set_private_key(key.get(), priv_key->get())) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid private key: ", internal::GetSslErrors()));
  }

  // Check that EC_KEY is valid.
  if (!EC_KEY_check_key(key.get())) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid EC key pair: ", internal::GetSslErrors()));
  }

  return util::OkStatus();
}

util::Status ValidateX25519KeyPair(absl::string_view public_key_bytes,
                                   const util::SecretData& private_key_bytes) {
  util::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::X25519KeyFromPrivateKey(private_key_bytes);
  if (!x25519_key.ok()) {
    return x25519_key.status();
  }
  auto public_key_bytes_from_private = absl::string_view(
      reinterpret_cast<const char*>((*x25519_key)->public_value),
      internal::X25519KeyPubKeySize());
  if (public_key_bytes != public_key_bytes_from_private) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "X25519 private key does not match the specified X25519 public key.");
  }
  return util::OkStatus();
}

util::Status ValidateKeyPair(const HpkePublicKey& public_key,
                             const RestrictedData& private_key_bytes,
                             PartialKeyAccessToken token) {
  HpkeParameters::KemId kem_id = public_key.GetParameters().GetKemId();
  absl::string_view public_key_bytes = public_key.GetPublicKeyBytes(token);
  util::SecretData secret = util::SecretDataFromStringView(
      private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get()));

  if (IsNistKem(kem_id)) {
    util::StatusOr<subtle::EllipticCurveType> curve =
        CurveTypeFromKemId(kem_id);
    if (!curve.ok()) {
      return curve.status();
    }
    return ValidateNistEcKeyPair(*curve, public_key_bytes, secret);
  }
  return ValidateX25519KeyPair(public_key_bytes, secret);
}

}  // namespace

util::StatusOr<HpkePrivateKey> HpkePrivateKey::Create(
    const HpkePublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
  util::Status key_length_validation = ValidatePrivateKeyLength(
      public_key.GetParameters().GetKemId(), private_key_bytes.size());
  if (!key_length_validation.ok()) {
    return key_length_validation;
  }
  util::Status key_pair_validation =
      ValidateKeyPair(public_key, private_key_bytes, token);
  if (!key_pair_validation.ok()) {
    return key_pair_validation;
  }
  return HpkePrivateKey(public_key, private_key_bytes);
}

bool HpkePrivateKey::operator==(const Key& other) const {
  const HpkePrivateKey* that = dynamic_cast<const HpkePrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (public_key_ != that->public_key_) {
    return false;
  }
  return private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
