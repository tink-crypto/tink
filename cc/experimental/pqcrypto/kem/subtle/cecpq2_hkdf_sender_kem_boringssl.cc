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

#include "tink/experimental/pqcrypto/kem/subtle/cecpq2_hkdf_sender_kem_boringssl.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "openssl/curve25519.h"
#include "openssl/hrss.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {
namespace subtle {

// This method only redirects the object creation to the appropriate class
// based on the chosen curve. As of now, the only curve supported is
// Curve25519. This method was designed to be generic enough to faciliate the
// extension of this hybrid KEM to support other curves.
// static
util::StatusOr<std::unique_ptr<const Cecpq2HkdfSenderKemBoringSsl>>
Cecpq2HkdfSenderKemBoringSsl::New(subtle::EllipticCurveType curve,
                                  const absl::string_view ec_pubx,
                                  const absl::string_view ec_puby,
                                  const absl::string_view marshalled_hrss_pub) {
  switch (curve) {
    case EllipticCurveType::CURVE25519:
      return Cecpq2HkdfX25519SenderKemBoringSsl::New(curve, ec_pubx, ec_puby,
                                                     marshalled_hrss_pub);
    default:
      return util::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
}

Cecpq2HkdfX25519SenderKemBoringSsl::Cecpq2HkdfX25519SenderKemBoringSsl(
    const absl::string_view peer_ec_pubx,
    const absl::string_view marshalled_hrss_pub) {
  peer_public_key_x25519_.assign(std::string(peer_ec_pubx));
  peer_marshalled_public_key_hrss_.assign(std::string(marshalled_hrss_pub));
}

// static
util::StatusOr<std::unique_ptr<const Cecpq2HkdfSenderKemBoringSsl>>
Cecpq2HkdfX25519SenderKemBoringSsl::New(
    subtle::EllipticCurveType curve, const absl::string_view pubx,
    const absl::string_view puby, const absl::string_view marshalled_hrss_pub) {
  auto status =
      internal::CheckFipsCompatibility<Cecpq2HkdfX25519SenderKemBoringSsl>();
  if (!status.ok()) return status;

  // Basic input checking
  if (curve != CURVE25519) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "curve is not CURVE25519");
  }
  if (pubx.size() != X25519_PUBLIC_VALUE_LEN) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "pubx has unexpected length");
  }
  if (!puby.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "puby is not empty");
  }
  if (marshalled_hrss_pub.size() != HRSS_PUBLIC_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "marshalled_hrss_pub has unexpected length");
  }

  // If input parameters are ok, create a CECPQ2 Sender KEM instance
  std::unique_ptr<const Cecpq2HkdfSenderKemBoringSsl> sender_kem(
      new Cecpq2HkdfX25519SenderKemBoringSsl(pubx, marshalled_hrss_pub));
  return std::move(sender_kem);
}

util::StatusOr<std::unique_ptr<const Cecpq2HkdfSenderKemBoringSsl::KemKey>>
Cecpq2HkdfX25519SenderKemBoringSsl::GenerateKey(
    subtle::HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    subtle::EcPointFormat point_format) const {
  // Basic input validation:
  if (point_format != EcPointFormat::COMPRESSED) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "X25519 only supports compressed elliptic curve points");
  }
  if (key_size_in_bytes < 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "key size length is smaller than 32 bytes "
                        "and thus not post-quantum secure.");
  }

  // Generate the ephemeral X25519 key pair. Note that the
  // X25519_kem_bytes holds the X25519 public key
  util::SecretData ephemeral_x25519_private_key(X25519_PRIVATE_KEY_LEN);
  std::string x25519_kem_bytes(X25519_PUBLIC_VALUE_LEN, '\0');
  X25519_keypair(const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(
                     x25519_kem_bytes.data())),
                 ephemeral_x25519_private_key.data());

  // Generate the x25519 shared secret using peer's X25519 public key and
  // locally generated ephemeral X25519 private key
  util::SecretData x25519_shared_secret(X25519_SHARED_KEY_LEN);
  X25519(x25519_shared_secret.data(), ephemeral_x25519_private_key.data(),
         reinterpret_cast<const uint8_t *>(peer_public_key_x25519_.data()));

  // Declare the hrss_shared_secret and hrss_kem_bytes to be used in HRSS encaps
  util::SecretData hrss_shared_secret;
  hrss_shared_secret.resize(HRSS_KEY_BYTES);
  // The hrss_kem_bytes will contain the encrypted shared secret
  std::string hrss_kem_bytes;
  subtle::ResizeStringUninitialized(&hrss_kem_bytes, HRSS_CIPHERTEXT_BYTES);

  // Recover the internal HRSS public key representation from marshalled version
  struct HRSS_public_key peer_public_key_hrss;
  HRSS_parse_public_key(&peer_public_key_hrss,
                        reinterpret_cast<const uint8_t *>(
                            peer_marshalled_public_key_hrss_.data()));

  // Generate entropy to be used in encaps
  util::SecretData encaps_entropy =
      crypto::tink::subtle::Random::GetRandomKeyBytes(HRSS_ENCAP_BYTES);

  // Generate a random shared secret and encapsulate it using peer's HRSS public
  // key
  HRSS_encap(const_cast<uint8_t *>(
                 reinterpret_cast<const uint8_t *>(hrss_kem_bytes.data())),
             reinterpret_cast<uint8_t *>(hrss_shared_secret.data()),
             &peer_public_key_hrss, encaps_entropy.data());

  // Concatenate the two kem_bytes
  std::string kem_bytes(x25519_kem_bytes);
  kem_bytes += hrss_kem_bytes;

  // Concatenate the two shared secrets with the two kem_bytes
  std::string kem_bytes_and_shared_secrets = absl::StrCat(
      kem_bytes, util::SecretDataAsStringView(x25519_shared_secret),
      util::SecretDataAsStringView(hrss_shared_secret));
  util::SecretData ikm =
      util::SecretDataFromStringView(kem_bytes_and_shared_secrets);

  // Compute the symmetric key from the two shared secrets, kem_bytes, hkdf_salt
  // and hkdf_info using HKDF
  auto symmetric_key_or =
      Hkdf::ComputeHkdf(hash, ikm, hkdf_salt, hkdf_info, key_size_in_bytes);
  if (!symmetric_key_or.ok()) {
    return symmetric_key_or.status();
  }
  util::SecretData symmetric_key = symmetric_key_or.value();

  // Return the produced pair kem_bytes and symmetric_key
  return absl::make_unique<const KemKey>(kem_bytes, symmetric_key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
