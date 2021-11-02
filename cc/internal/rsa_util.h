// Copyright 2021 Google LLC
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
#ifndef TINK_INTERNAL_RSA_UTIL_H_
#define TINK_INTERNAL_RSA_UTIL_H_

#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

struct RsaPublicKey {
  // Modulus.
  // Unsigned big integer in bigendian representation.
  std::string n;
  // Public exponent.
  // Unsigned big integer in bigendian representation.
  std::string e;
};

// Parameters of RSA SSA (Signature Schemes with Appendix) using  PSS
// (Probabilistic Signature Scheme) encoding (see
// https://tools.ietf.org/html/rfc8017#section-8.1).
struct RsaSsaPssParams {
  // Hash function used in computing hash of the signing message
  // (see https://tools.ietf.org/html/rfc8017#section-9.1.1).
  subtle::HashType sig_hash;
  // Hash function used in MGF1 (a mask generation function based on a
  // hash function) (see https://tools.ietf.org/html/rfc8017#appendix-B.2.1).
  subtle::HashType mgf1_hash;
  // Salt length (see https://tools.ietf.org/html/rfc8017#section-9.1.1)
  int salt_length;
};

// Parameters of RSA SSA (Signature Schemes with Appendix) using PKCS1
// (Probabilistic Signature Scheme) encoding (see
// https://tools.ietf.org/html/rfc8017#section-8.2).
struct RsaSsaPkcs1Params {
  // Hash function used in computing hash of the signing message
  // (see https://tools.ietf.org/html/rfc8017#section-9.2).
  subtle::HashType hash_type;
};

// RSA private key representation.
struct RsaPrivateKey {
  // Modulus.
  std::string n;
  // Public exponent.
  std::string e;
  // Private exponent.
  // Unsigned big integer in bigendian representation.
  util::SecretData d;

  // The prime factor p of n.
  // Unsigned big integer in bigendian representation.
  util::SecretData p;
  // The prime factor q of n.
  // Unsigned big integer in bigendian representation.
  util::SecretData q;
  // d mod (p - 1).
  util::SecretData dp;
  // d mod (q - 1).
  // Unsigned big integer in bigendian representation.
  util::SecretData dq;
  // Chinese Remainder Theorem coefficient q^(-1) mod p.
  // Unsigned big integer in bigendian representation.
  util::SecretData crt;
};

// Validates whether 'modulus_size' is at least 2048-bit.
// To reach 128-bit security strength, RSA's modulus must be at least
// 3072-bit while 2048-bit RSA key only has 112-bit security. Nevertheless,
// a 2048-bit RSA key is considered safe by NIST until 2030 (see
// https://www.keylength.com/en/4/).
crypto::tink::util::Status ValidateRsaModulusSize(size_t modulus_size);

// Validates whether 'publicExponent' is odd and greater than 65536. The
// primes p and q are chosen such that (p-1)(q-1) is relatively prime to the
// public exponent. Therefore, the public exponent must be odd. Furthermore,
// choosing a public exponent which is not greater than 65536 can lead to weak
// instantiations of RSA. A public exponent which is odd and greater than
// 65536 conforms to the requirements set by NIST FIPS 186-4 (Appendix B.3.1).
crypto::tink::util::Status ValidateRsaPublicExponent(
    absl::string_view exponent);

// Creates a new RSA key pair and populates `private_key` and `public_key`.
crypto::tink::util::Status NewRsaKeyPair(int modulus_size_in_bits,
                                         const BIGNUM *e,
                                         RsaPrivateKey *private_key,
                                         RsaPublicKey *public_key);

// Returns `key`'s private and public exponents (d and e) and mosulus
// (n) writing a copy of them into `rsa`.
crypto::tink::util::Status GetRsaModAndExponents(const RsaPrivateKey &key,
                                                 RSA *rsa);

// Returns `key`'s prime factors (p and q) writing a copy of them into `rsa`.
crypto::tink::util::Status GetRsaPrimeFactors(const RsaPrivateKey &key,
                                              RSA *rsa);

// Returns `key`'s CRT parameters (dp and dq) writing a copy of them into `rsa`.
crypto::tink::util::Status GetRsaCrtParams(const RsaPrivateKey &key, RSA *rsa);

// Creates a OpenSSL/BoringSSL RSA key from `private_key`.
crypto::tink::util::StatusOr<internal::SslUniquePtr<RSA>> RsaPrivateKeyToRsa(
    const RsaPrivateKey &private_key);

// Creates a OpenSSL/BoringSSL RSA key from an `public_key`.
crypto::tink::util::StatusOr<internal::SslUniquePtr<RSA>> RsaPublicKeyToRsa(
    const RsaPublicKey &public_key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_RSA_UTIL_H_
