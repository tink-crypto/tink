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

#ifndef THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_SUBTLE_CECPQ2_HKDF_RECIPIENT_KEM_BORINGSSL_H_
#define THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_SUBTLE_CECPQ2_HKDF_RECIPIENT_KEM_BORINGSSL_H_

#include "absl/strings/string_view.h"
#include "openssl/curve25519.h"
#include "openssl/ec.h"
#include "openssl/hrss.h"
#include "tink/internal/fips_utils.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// This class implements the CECPQ2 hybrid KEM from the recipient's perspective,
// using Boring SSL for the underlying cryptographic operations.
// This class is made generic enough so that extending the ECC algorithm to
// support other curves is trivial. As of now, the only supported curve is
// Curve25519.
//
// CECPQ2 combines both X25519 KEM and NTRU-HRSS KEM into a single hybrid KEM.
// The NTRU-HRSS is a structured lattice-based key encapsulation mechanism. It
// was originally proposed in [1] and submitted to the NIST Post-Quantum
// Cryptography standardization process [2].
//
// During the course of the NIST PQC standardization process, the NTRU-HRSS
// proposal merged with another proposal (NTRUEncrypt). The resulting scheme,
// simply called NTRU [3], is a 3rd round finalist of the NIST PQC
// standardization process.
//
// The implementation available in BoringSSL is based on [1] but it
// uses a different KEM construction based on [4]. Similar path has been taken
// by the NTRU team in the NIST competition which later adopted [4] as their
// QROM security proof approach. Note that the BoringSSL implementation is *not*
// compatible with the 3rd Round finalist NTRU running in the NIST Post-Quantum
// Cryptography standardization process [5].
//
// References:
// [1]: https://eprint.iacr.org/2017/667.pdf
// [2]: https://csrc.nist.gov/Projects/post-quantum-cryptography/
// [3]: https://ntru.org/
// [4]: https://eprint.iacr.org/2017/1005.pdf
// [5]: https://ntru.org/release/NIST-PQ-Submission-NTRU-20201016.tar.gz
class Cecpq2HkdfRecipientKemBoringSsl {
 public:
  // Constructs a recipient KEM for the specified curve, recipient's ECC
  // private key, which must be a big-endian byte array, and recipient's HRSS
  // private key. This method is made generic enough so that extending the ECC
  // algorithm to support other curves is trivial.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<Cecpq2HkdfRecipientKemBoringSsl>>
  New(EllipticCurveType curve, util::SecretData ec_private_key,
      util::SecretData hrss_private_key_seed);

  virtual ~Cecpq2HkdfRecipientKemBoringSsl() = default;

  // Computes the shared secret from the ECC private key and peer's ECC encoded
  // public key, and the shared secret from the HRSS private key, then uses a
  // hkdf to derive the symmetric key from the two shared secrets, hkdf info and
  // hkdf salt. This method is made generic enough so that extending the ECC
  // algorithm to support other curves is trivial.
  virtual crypto::tink::util::StatusOr<util::SecretData> GenerateKey(
      absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
      absl::string_view hkdf_info, uint32_t key_size_in_bytes,
      EcPointFormat point_format) const = 0;
};

// Implementation of Cecpq2HkdfRecipientKemBoringSsl for Curve25519.
class Cecpq2HkdfX25519RecipientKemBoringSsl
    : public Cecpq2HkdfRecipientKemBoringSsl {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  // Constructs a recipient CECPQ2 KEM for recipient's X25519 private key,
  // which must be a big-endian byte array, and recipient's HRSS private key.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<Cecpq2HkdfRecipientKemBoringSsl>>
  New(EllipticCurveType curve, util::SecretData ec_private_key,
      util::SecretData hrss_private_key_seed);

  // Computes the shared secret from X25519 private key and peer's X25519
  // encoded public key, and the shared secret from the HRSS private key, then
  // uses a hkdf to derive the symmetric key from the two shared secrets, hkdf
  // info and hkdf salt.
  crypto::tink::util::StatusOr<util::SecretData> GenerateKey(
      absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
      absl::string_view hkdf_info, uint32_t key_size_in_bytes,
      EcPointFormat point_format) const override;

 private:
  // The private constructor only takes the X25519 and HRSS private keys and
  // assign them to the class private members.
  explicit Cecpq2HkdfX25519RecipientKemBoringSsl(
      util::SecretData ec_private_key, util::SecretData hrss_private_key_seed)
      : private_key_x25519_(std::move(ec_private_key)),
        private_key_hrss_seed_(std::move(hrss_private_key_seed)) {}

  // X25519 and HRSS private key containers
  util::SecretData private_key_x25519_;
  util::SecretData private_key_hrss_seed_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_SUBTLE_CECPQ2_HKDF_RECIPIENT_KEM_BORINGSSL_H_
