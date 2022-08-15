// Copyright 2020 Google LLC
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

#include "tink/experimental/pqcrypto/kem/subtle/cecpq2_hkdf_recipient_kem_boringssl.h"

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "openssl/curve25519.h"
#include "openssl/ec.h"
#include "openssl/hrss.h"
#include "tink/experimental/pqcrypto/kem/subtle/cecpq2_hkdf_sender_kem_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/util/errors.h"

namespace crypto {
namespace tink {
namespace subtle {

// This method only redirects the object creation to the appropriate class
// based on the chosen curve. As of now, the only curve supported is
// Curve25519. This method was designed to be generic enough to faciliate the
// extension of this hybrid KEM to support other curves.
// static
util::StatusOr<std::unique_ptr<Cecpq2HkdfRecipientKemBoringSsl>>
Cecpq2HkdfRecipientKemBoringSsl::New(EllipticCurveType curve,
                                     util::SecretData ec_private_key,
                                     util::SecretData hrss_private_key_seed) {
  switch (curve) {
    case EllipticCurveType::CURVE25519:
      return Cecpq2HkdfX25519RecipientKemBoringSsl::New(
          curve, std::move(ec_private_key), std::move(hrss_private_key_seed));
    default:
      return util::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
}

// static
util::StatusOr<std::unique_ptr<Cecpq2HkdfRecipientKemBoringSsl>>
Cecpq2HkdfX25519RecipientKemBoringSsl::New(
    EllipticCurveType curve, util::SecretData ec_private_key,
    util::SecretData hrss_private_key_seed) {
  auto status =
      internal::CheckFipsCompatibility<Cecpq2HkdfX25519RecipientKemBoringSsl>();
  if (!status.ok()) return status;

  // Basic input checking
  if (curve != CURVE25519) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "curve is not CURVE25519");
  }
  if (ec_private_key.size() != X25519_PRIVATE_KEY_LEN) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "priv has unexpected length");
  }
  // If all input parameters are ok, create a CECPQ2 Recipient KEM instance
  return {absl::WrapUnique(new Cecpq2HkdfX25519RecipientKemBoringSsl(
      std::move(ec_private_key), std::move(hrss_private_key_seed)))};
}

crypto::tink::util::StatusOr<util::SecretData>
Cecpq2HkdfX25519RecipientKemBoringSsl::GenerateKey(
    absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    EcPointFormat point_format) const {
  // Basic input checking
  if (point_format != EcPointFormat::COMPRESSED) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "X25519 only supports compressed elliptic curve points");
  }
  if (kem_bytes.size() != X25519_PUBLIC_VALUE_LEN + HRSS_PUBLIC_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "kem_bytes has unexpected size");
  }
  if (key_size_in_bytes < 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "key size length is smaller than 32 bytes "
                        "and thus not post-quantum secure.");
  }

  // Recover X25519 shared secret
  util::SecretData x25519_shared_secret(X25519_SHARED_KEY_LEN);
  X25519(x25519_shared_secret.data(), private_key_x25519_.data(),
         reinterpret_cast<const uint8_t*>(kem_bytes.data()));

  // Regenerate HRSS key pair from seed
  util::SecretUniquePtr<struct HRSS_private_key> hrss_private_key =
      util::MakeSecretUniquePtr<struct HRSS_private_key>();
  struct HRSS_public_key hrss_public_key;
  HRSS_generate_key(&hrss_public_key, hrss_private_key.get(),
                    private_key_hrss_seed_.data());

  // Recover HRSS shared secret from kem_bytes and private key
  util::SecretData hrss_shared_secret(HRSS_KEY_BYTES);
  HRSS_decap(reinterpret_cast<uint8_t*>(hrss_shared_secret.data()),
             hrss_private_key.get(),
             reinterpret_cast<const uint8_t*>(kem_bytes.data() +
                                              X25519_PUBLIC_VALUE_LEN),
             HRSS_CIPHERTEXT_BYTES);

  // Concatenate both shared secrets and kem_bytes
  util::SecretData ikm = util::SecretDataFromStringView(absl::StrCat(
      kem_bytes, util::SecretDataAsStringView(x25519_shared_secret),
      util::SecretDataAsStringView(hrss_shared_secret)));

  // Compute symmetric key from both shared secrets, kem_bytes, hkdf_salt and
  // hkdf_info using HKDF
  auto symmetric_key_or =
      Hkdf::ComputeHkdf(hash, ikm, hkdf_salt, hkdf_info, key_size_in_bytes);
  if (!symmetric_key_or.ok()) {
    return symmetric_key_or.status();
  }
  util::SecretData symmetric_key = symmetric_key_or.value();

  return symmetric_key;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
