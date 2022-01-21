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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_CECPQ2_SUBTLE_CECPQ2_HKDF_SENDER_KEM_BORINGSSL_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_CECPQ2_SUBTLE_CECPQ2_HKDF_SENDER_KEM_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

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

// This class implements the CECPQ2 hybrid KEM from the sender's perspective,
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
class Cecpq2HkdfSenderKemBoringSsl {
 public:
  // Container for the generated key and associated kem_bytes data.
  class KemKey {
   public:
    KemKey() = default;
    explicit KemKey(std::string kem_bytes, util::SecretData symmetric_key)
        : kem_bytes_(std::move(kem_bytes)),
          symmetric_key_(std::move(symmetric_key)) {}
    const std::string& get_kem_bytes() const { return kem_bytes_; }
    const util::SecretData& get_symmetric_key() const { return symmetric_key_; }

   private:
    // The kem_bytes variable stores both X25519 and HRSS kem_bytes in a
    // contiguous form. We note that for X25519, the kem_bytes consists of the
    // X25519 public key, while for HRSS it is the encrypted shared secret.
    std::string kem_bytes_;
    util::SecretData symmetric_key_;
  };

  // Constructs a sender CECPQ2 KEM for recipient's ECC public key, which must
  // be a big-endian byte array, and recipient's HRSS public key. This method is
  // made generic enough so that extending the ECC algorithm to support other
  // curves is trivial.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<const Cecpq2HkdfSenderKemBoringSsl>>
  New(EllipticCurveType curve, const absl::string_view ec_pubx,
      const absl::string_view ec_puby,
      const absl::string_view marshalled_hrss_pub);

  // Generates ephemeral key pairs, computes ECC's shared secret based on
  // generated ephemeral key and recipient's public key, generate a random
  // shared secret and encapsulates it using recipient's HRSS public key.
  // Then it uses HKDF to derive the symmetric key from both shared secrets,
  // 'hkdf_info' and hkdf_salt. This method is made generic enough so that
  // extending the ECC algorithm to support other curves is trivial.
  virtual crypto::tink::util::StatusOr<std::unique_ptr<const KemKey>>
  GenerateKey(HashType hash, absl::string_view hkdf_salt,
              absl::string_view hkdf_info, uint32_t key_size_in_bytes,
              EcPointFormat point_format) const = 0;

  virtual ~Cecpq2HkdfSenderKemBoringSsl() = default;
};

// Implementation of Cecpq2HkdfSenderKemBoringSsl for X25519 and HRSS.
class Cecpq2HkdfX25519SenderKemBoringSsl : public Cecpq2HkdfSenderKemBoringSsl {
 public:
  // Constructs a sender CECPQ2 KEM for recipient's X25519 public key, which
  // must be a big-endian byte array, and recipient's HRSS public key.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<const Cecpq2HkdfSenderKemBoringSsl>>
  New(EllipticCurveType curve, const absl::string_view pubx,
      const absl::string_view puby,
      const absl::string_view marshalled_hrss_pub);

  // Generates an ephemeral X25519 key pair, computes the X25519's shared secret
  // based on the ephemeral key and recipient's public key, generates a random
  // shared secret and encapsulates it using the recipient's HRSS public key.
  // Then it uses HKDF to derive the symmetric key from both shared secrets,
  // 'hkdf_info' and hkdf_salt.
  crypto::tink::util::StatusOr<std::unique_ptr<const KemKey>> GenerateKey(
      HashType hash, absl::string_view hkdf_salt, absl::string_view hkdf_info,
      uint32_t key_size_in_bytes, EcPointFormat point_format) const override;

  // Flag to indicate CECPQ2 is not FIPS compliant
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  // The private constructor only takes the X25519 and HRSS public keys. The
  // curve is not provided as a parameter here because the curve validation has
  // already been made in the New() method defined above.
  explicit Cecpq2HkdfX25519SenderKemBoringSsl(
      const absl::string_view peer_ec_pubx,
      const absl::string_view marshalled_hrss_pub);

  // X25519 and HRSS public key containers. We note that the BoringSSL
  // implementation of HRSS requires that the HRSS public key is stored in the
  // *marshalled* format. This is done by calling the HRSS_marshal_public_key
  // function from BoringSSL (see the tests available in cecpq2_hkdf_sender_kem
  // _boringssl_test.cc file that demonstrate this process). If this process is
  // not done, the internal raw HRSS public key representation (using the struct
  // HRSS_public_key data structure) might cause padding problems depending on
  // the compiler options.
  // X25519 public key of size X25519_PUBLIC_VALUE_LEN
  std::string peer_public_key_x25519_;
  // HRSS public key of size HRSS_PUBLIC_KEY_BYTES
  std::string peer_marshalled_public_key_hrss_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_CECPQ2_SUBTLE_CECPQ2_HKDF_SENDER_KEM_BORINGSSL_H_
