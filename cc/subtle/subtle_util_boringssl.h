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

#include "absl/base/attributes.h"
#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/cipher.h"
#include "openssl/curve25519.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
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

  using RsaPublicKey ABSL_DEPRECATED(
      "Use of this type is dicouraged outside Tink.") = internal::RsaPublicKey;
  using RsaSsaPssParams ABSL_DEPRECATED(
      "Use of this type is dicouraged outside Tink.") =
      internal::RsaSsaPssParams;
  using RsaSsaPkcs1Params ABSL_DEPRECATED(
      "Use of this type is dicouraged outside Tink.") =
      internal::RsaSsaPkcs1Params;
  using RsaPrivateKey ABSL_DEPRECATED(
      "Use of this type is dicouraged outside Tink.") = internal::RsaPrivateKey;

  // Returns BoringSSL's BIGNUM constructed from bigendian string
  // representation.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::StatusOr<internal::SslUniquePtr<BIGNUM>> str2bn(
      absl::string_view s) {
    return internal::StringToBignum(s);
  }

  // Returns a SecretData of size 'len' that holds BIGNUM 'bn'.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::StatusOr<std::string> bn2str(const BIGNUM *bn,
                                                   size_t len) {
    return internal::BignumToString(bn, len);
  }

  // Returns a string of size 'len' that holds BIGNUM 'bn'.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::StatusOr<util::SecretData> BignumToSecretData(
      const BIGNUM *bn, size_t len) {
    return internal::BignumToSecretData(bn, len);
  }

  // Returns BoringSSL error strings accumulated in the error queue,
  // thus emptying the queue.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline std::string GetErrors() { return internal::GetSslErrors(); }

  // Returns BoringSSL's EC_GROUP constructed from the curve type.
  static crypto::tink::util::StatusOr<EC_GROUP *> GetEcGroup(
      EllipticCurveType curve_type);

  // Returns BoringSSL's EC_POINT constructed from the curve type, big-endian
  // representation of public key's x-coordinate and y-coordinate.
  static crypto::tink::util::StatusOr<EC_POINT *> GetEcPoint(
      EllipticCurveType curve, absl::string_view pubx, absl::string_view puby);

  // Returns the curve type associated with the EC_GROUP
  static crypto::tink::util::StatusOr<EllipticCurveType> GetCurve(
      const EC_GROUP *group);

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

  // Return an empty string if str.data() is nullptr; otherwise return str.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline absl::string_view EnsureNonNull(absl::string_view str) {
    return internal::EnsureStringNonNull(str);
  }

  // Validates whether 'sig_hash' is safe to use for digital signature.
  static crypto::tink::util::Status ValidateSignatureHash(
      subtle::HashType sig_hash);

  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline crypto::tink::util::Status ValidateRsaModulusSize(
      size_t modulus_size) {
    return internal::ValidateRsaModulusSize(modulus_size);
  }

  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline crypto::tink::util::Status ValidateRsaPublicExponent(
      absl::string_view exponent) {
    return internal::ValidateRsaPublicExponent(exponent);
  }

  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::Status GetNewRsaKeyPair(int modulus_size_in_bits,
                                              const BIGNUM *e,
                                              RsaPrivateKey *private_key,
                                              RsaPublicKey *public_key) {
    return internal::NewRsaKeyPair(modulus_size_in_bits, e, private_key,
                                   public_key);
  }

  // Copies n, e and d into the RSA key.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::Status CopyKey(const RsaPrivateKey &key, RSA *rsa) {
    return internal::GetRsaModAndExponents(key, rsa);
  }

  // Copies the prime factors (p, q) into the RSA key.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::Status CopyPrimeFactors(const RsaPrivateKey &key,
                                              RSA *rsa) {
    return internal::GetRsaPrimeFactors(key, rsa);
  }

  // Copies the CRT params and dp, dq into the RSA key.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::Status CopyCrtParams(const RsaPrivateKey &key, RSA *rsa) {
    return internal::GetRsaCrtParams(key, rsa);
  }

  // Creates a BoringSSL RSA key from an RsaPrivateKey.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::StatusOr<internal::SslUniquePtr<RSA>>
  BoringSslRsaFromRsaPrivateKey(const RsaPrivateKey &key) {
    return internal::RsaPrivateKeyToRsa(key);
  }

  // Creates a BoringSSL RSA key from an RsaPublicKey.
  ABSL_DEPRECATED("Use of this function is dicouraged outside Tink.")
  static inline util::StatusOr<internal::SslUniquePtr<RSA>>
  BoringSslRsaFromRsaPublicKey(const RsaPublicKey &key) {
    return internal::RsaPublicKeyToRsa(key);
  }

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
