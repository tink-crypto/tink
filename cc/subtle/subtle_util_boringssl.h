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

#ifndef TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_
#define TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_

#include <cstdint>
#include <vector>

#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/cipher.h"
#include "openssl/curve25519.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class SubtleUtilBoringSSL {
 public:
  struct EcKey {
    EllipticCurveType curve;
    std::string pub_x;  // affine coordinates in bigendian representation
    std::string pub_y;
    util::SecretData priv;  // big integer in bigendian representation
  };

  struct X25519Key {
    uint8_t public_value[X25519_PUBLIC_VALUE_LEN];
    uint8_t private_key[X25519_PRIVATE_KEY_LEN];
  };

  struct Ed25519Key {
    std::string public_key;
    std::string private_key;
  };

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
    HashType sig_hash;
    // Hash function used in MGF1 (a mask generation function based on a
    // hash function) (see https://tools.ietf.org/html/rfc8017#appendix-B.2.1).
    HashType mgf1_hash;
    // Salt length (see https://tools.ietf.org/html/rfc8017#section-9.1.1)
    int salt_length;
  };

  // Parameters of RSA SSA (Signature Schemes with Appendix) using PKCS1
  // (Probabilistic Signature Scheme) encoding (see
  // https://tools.ietf.org/html/rfc8017#section-8.2).
  struct RsaSsaPkcs1Params {
    // Hash function used in computing hash of the signing message
    // (see https://tools.ietf.org/html/rfc8017#section-9.2).
    HashType hash_type;
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

  // Returns BoringSSL's BIGNUM constructed from bigendian string
  // representation.
  static util::StatusOr<internal::SslUniquePtr<BIGNUM>> str2bn(
      absl::string_view s);

  // Returns a string of size 'len' that holds BIGNUM 'bn'.
  static util::StatusOr<std::string> bn2str(const BIGNUM *bn, size_t len);

  // Returns a SecretData of size 'len' that holds BIGNUM 'bn'.
  static util::StatusOr<util::SecretData> BignumToSecretData(const BIGNUM *bn,
                                                             size_t len);

  // Returns BoringSSL error strings accumulated in the error queue,
  // thus emptying the queue.
  static std::string GetErrors();

  // Returns BoringSSL's EC_GROUP constructed from the curve type.
  static crypto::tink::util::StatusOr<EC_GROUP *> GetEcGroup(
      EllipticCurveType curve_type);

  // Returns BoringSSL's EC_POINT constructed from the curve type, big-endian
  // representation of public key's x-coordinate and y-coordinate.
  static crypto::tink::util::StatusOr<EC_POINT *> GetEcPoint(
      EllipticCurveType curve, absl::string_view pubx, absl::string_view puby);

  // Returns a new EC key for the specified curve.
  static crypto::tink::util::StatusOr<EcKey> GetNewEcKey(
      EllipticCurveType curve_type);

  // Returns a new EC key for the specified curve derived from a seed.
  static crypto::tink::util::StatusOr<EcKey> GetNewEcKeyFromSeed(
      EllipticCurveType curve_type, const util::SecretData &secret_seed);

  // Returns a new X25519 key.
  static std::unique_ptr<X25519Key> GenerateNewX25519Key();

  // Returns a X25519Key matching the specified EcKey.
  static crypto::tink::util::StatusOr<std::unique_ptr<X25519Key>>
  X25519KeyFromEcKey(const EcKey &ec_key);

  // Returns an EcKey matching the specified X25519Key.
  static EcKey EcKeyFromX25519Key(const X25519Key *x25519_key);

  // Returns a new ED25519 key.
  static std::unique_ptr<Ed25519Key> GetNewEd25519Key();

  // Returns a new ED25519 key generated from a 32-byte secret seed.
  static std::unique_ptr<Ed25519Key> GetNewEd25519KeyFromSeed(
      const util::SecretData &secret_seed);

  // Returns BoringSSL's EC_POINT constructed from curve type, point format and
  // encoded public key's point. The uncompressed point is encoded as
  // 0x04 || x || y where x, y are curve_size_in_bytes big-endian byte array.
  // The compressed point is encoded as 1-byte || x where x is
  // curve_size_in_bytes big-endian byte array and if the least significant bit
  // of y is 1, the 1st byte is 0x03, otherwise it's 0x02.
  static util::StatusOr<internal::SslUniquePtr<EC_POINT>> EcPointDecode(
      EllipticCurveType curve, EcPointFormat format, absl::string_view encoded);

  // Returns the encoded public key based on curve type, point format and
  // BoringSSL's EC_POINT public key point. The uncompressed point is encoded as
  // 0x04 || x || y where x, y are curve_size_in_bytes big-endian byte array.
  // The compressed point is encoded as 1-byte || x where x is
  // curve_size_in_bytes big-endian byte array and if the least significant bit
  // of y is 1, the 1st byte is 0x03, otherwise it's 0x02.
  static crypto::tink::util::StatusOr<std::string> EcPointEncode(
      EllipticCurveType curve, EcPointFormat format, const EC_POINT *point);

  // Returns the ECDH's shared secret based on our private key and peer's public
  // key. Returns error if the public key is not on private key's curve.
  static crypto::tink::util::StatusOr<util::SecretData> ComputeEcdhSharedSecret(
      EllipticCurveType curve, const BIGNUM *priv_key, const EC_POINT *pub_key);

  // Transforms ECDSA IEEE_P1363 signature encoding to DER encoding.
  //
  // The IEEE_P1363 signature's format is r || s, where r and s are zero-padded
  // and have the same size in bytes as the order of the curve. For example, for
  // NIST P-256 curve, r and s are zero-padded to 32 bytes.
  //
  // The DER signature is encoded using ASN.1
  // (https://tools.ietf.org/html/rfc5480#appendix-A):
  //   ECDSA-Sig-Value :: = SEQUENCE { r INTEGER, s INTEGER }.
  // In particular, the encoding is:
  //   0x30 || totalLength || 0x02 || r's length || r || 0x02 || s's length || s
  static crypto::tink::util::StatusOr<std::string> EcSignatureIeeeToDer(
      const EC_GROUP *group, absl::string_view ieee_sig);

  // Returns an EVP structure for a hash function.
  // The EVP_MD instances are sigletons owned by BoringSSL.
  static crypto::tink::util::StatusOr<const EVP_MD *> EvpHash(
      HashType hash_type);

  // Validates whether 'sig_hash' is safe to use for digital signature.
  static crypto::tink::util::Status ValidateSignatureHash(
      subtle::HashType sig_hash);

  // Validates whether 'modulus_size' is at least 2048-bit.
  // To reach 128-bit security strength, RSA's modulus must be at least
  // 3072-bit while 2048-bit RSA key only has 112-bit security. Nevertheless,
  // a 2048-bit RSA key is considered safe by NIST until 2030 (see
  // https://www.keylength.com/en/4/).
  static crypto::tink::util::Status ValidateRsaModulusSize(size_t modulus_size);

  // Validates whether 'publicExponent' is odd and greater than 65536. The
  // primes p and q are chosen such that (p-1)(q-1) is relatively prime to the
  // public exponent. Therefore, the public exponent must be odd. Furthermore,
  // choosing a public exponent which is not greater than 65536 can lead to weak
  // instantiations of RSA. A public exponent which is odd and greater than
  // 65536 conforms to the requirements set by NIST FIPS 186-4 (Appendix B.3.1).
  static crypto::tink::util::Status ValidateRsaPublicExponent(
      absl::string_view exponent);

  // Return an empty string if str.data() is nullptr; otherwise return str.
  static absl::string_view EnsureNonNull(absl::string_view str);

  // Creates a new RSA public and private key pair.
  static util::Status GetNewRsaKeyPair(int modulus_size_in_bits,
                                       const BIGNUM *e,
                                       RsaPrivateKey *private_key,
                                       RsaPublicKey *public_key);

  // Copies n, e and d into the RSA key.
  static util::Status CopyKey(const RsaPrivateKey &key, RSA *rsa);

  // Copies the prime factors (p, q) into the RSA key.
  static util::Status CopyPrimeFactors(const RsaPrivateKey &key, RSA *rsa);

  // Copies the CRT params and dp, dq into the RSA key.
  static util::Status CopyCrtParams(const RsaPrivateKey &key, RSA *rsa);

  // Creates a BoringSSL RSA key from an RsaPrivateKey.
  static util::StatusOr<internal::SslUniquePtr<RSA>>
  BoringSslRsaFromRsaPrivateKey(const RsaPrivateKey &key);

  // Creates a BoringSSL RSA key from an RsaPublicKey.
  static util::StatusOr<internal::SslUniquePtr<RSA>>
  BoringSslRsaFromRsaPublicKey(const RsaPublicKey &key);

  // Returns BoringSSL's AES CTR EVP_CIPHER for the key size.
  ABSL_DEPRECATED("Use the equivalent in aead/internal/aead_util instead.")
  static const EVP_CIPHER *GetAesCtrCipherForKeySize(uint32_t size_in_bytes);

  // Returns BoringSSL's AES GCM EVP_CIPHER for the key size.
  ABSL_DEPRECATED("Use the equivalent in aead/internal/aead_util instead.")
  static const EVP_CIPHER *GetAesGcmCipherForKeySize(uint32_t size_in_bytes);

#ifdef OPENSSL_IS_BORINGSSL
  // Returns BoringSSL's AES GCM EVP_AEAD for the key size.
  ABSL_DEPRECATED("Use the equivalent in aead/internal/aead_util instead.")
  static const EVP_AEAD *GetAesGcmAeadForKeySize(uint32_t size_in_bytes);
#endif
};

namespace boringssl {

// Computes hash of 'input' using the hash function 'hasher'.
util::StatusOr<std::vector<uint8_t>> ComputeHash(absl::string_view input,
                                                 const EVP_MD &hasher);

}  // namespace boringssl
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_
