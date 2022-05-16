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

#ifndef TINK_SUBTLE_ECIES_HKDF_RECIPIENT_KEM_BORINGSSL_H_
#define TINK_SUBTLE_ECIES_HKDF_RECIPIENT_KEM_BORINGSSL_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// HKDF-based KEM (key encapsulation mechanism) for ECIES recipient,
// using Boring SSL for the underlying cryptographic operations.
class EciesHkdfRecipientKemBoringSsl {
 public:
  // Constructs a recipient KEM for the specified curve and recipient's
  // private key, which must be a big-endian byte array.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
  New(EllipticCurveType curve, util::SecretData priv_key);

  // Computes the ecdh's shared secret from our private key and peer's encoded
  // public key, then uses hkdf to derive the symmetric key from the shared
  // secret, hkdf info and hkdf salt.
  virtual crypto::tink::util::StatusOr<util::SecretData> GenerateKey(
      absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
      absl::string_view hkdf_info, uint32_t key_size_in_bytes,
      EcPointFormat point_format) const = 0;

  virtual ~EciesHkdfRecipientKemBoringSsl() = default;
};

// Implementation of EciesHkdfRecipientKemBoringSsl for the NIST P-curves.
class EciesHkdfNistPCurveRecipientKemBoringSsl
    : public EciesHkdfRecipientKemBoringSsl {
 public:
  // Constructs a recipient KEM for the specified curve and recipient's
  // private key, which must be a big-endian byte array.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
  New(EllipticCurveType curve, util::SecretData priv_key);

  // Computes the ecdh's shared secret from our private key and peer's encoded
  // public key, then uses hkdf to derive the symmetric key from the shared
  // secret, hkdf info and hkdf salt.
  crypto::tink::util::StatusOr<util::SecretData> GenerateKey(
      absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
      absl::string_view hkdf_info, uint32_t key_size_in_bytes,
      EcPointFormat point_format) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  EciesHkdfNistPCurveRecipientKemBoringSsl(
      EllipticCurveType curve, util::SecretData priv_key_value,
      internal::SslUniquePtr<EC_GROUP> ec_group);

  EllipticCurveType curve_;
  util::SecretData priv_key_value_;
  internal::SslUniquePtr<EC_GROUP> ec_group_;
};

// Implementation of EciesHkdfRecipientKemBoringSsl for curve25519.
class EciesHkdfX25519RecipientKemBoringSsl
    : public EciesHkdfRecipientKemBoringSsl {
 public:
  // Constructs a recipient KEM for the specified curve and recipient's
  // private key, which must be a big-endian byte array.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
  New(EllipticCurveType curve, util::SecretData priv_key);

  // Computes the ecdh's shared secret from our private key and peer's encoded
  // public key, then uses hkdf to derive the symmetric key from the shared
  // secret, hkdf info and hkdf salt.
  crypto::tink::util::StatusOr<util::SecretData> GenerateKey(
      absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
      absl::string_view hkdf_info, uint32_t key_size_in_bytes,
      EcPointFormat point_format) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  explicit EciesHkdfX25519RecipientKemBoringSsl(
      internal::SslUniquePtr<EVP_PKEY> private_key);

  const internal::SslUniquePtr<EVP_PKEY> private_key_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ECIES_HKDF_RECIPIENT_KEM_BORINGSSL_H_
