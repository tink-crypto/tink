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

#include <vector>

#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "tink/subtle/common_enums.h"
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
    std::string priv;  // big integer in bigendian represnetation
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
    std::string d;

    // The prime factor p of n.
    // Unsigned big integer in bigendian representation.
    std::string p;
    // The prime factor q of n.
    // Unsigned big integer in bigendian representation.
    std::string q;
    // d mod (p - 1).
    std::string dp;
    // d mod (q - 1).
    // Unsigned big integer in bigendian representation.
    std::string dq;
    // Chinese Remainder Theorem coefficient q^(-1) mod p.
    // Unsigned big integer in bigendian representation.
    std::string crt;
  };

  // Returns BoringSSL's BIGNUM constructed from bigendian std::string
  // representation.
  static util::StatusOr<bssl::UniquePtr<BIGNUM>> str2bn(absl::string_view s);

  // Returns a std::string of size 'len' that holds BIGNUM 'bn'.
  static util::StatusOr<std::string> bn2str(const BIGNUM *bn, size_t len);

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

  // Returns BoringSSL's EC_POINT constructed from curve type, point format and
  // encoded public key's point. The uncompressed point is encoded as
  // 0x04 || x || y where x, y are curve_size_in_bytes big-endian byte array.
  // The compressed point is encoded as 1-byte || x where x is
  // curve_size_in_bytes big-endian byte array and if the least significant bit
  // of y is 1, the 1st byte is 0x03, otherwise it's 0x02.
  static crypto::tink::util::StatusOr<EC_POINT *> EcPointDecode(
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
  static crypto::tink::util::StatusOr<std::string> ComputeEcdhSharedSecret(
      EllipticCurveType curve, const BIGNUM *priv_key, const EC_POINT *pub_key);

  // Returns an EVP structure for a hash function.
  // The EVP_MD instances are sigletons owned by BoringSSL.
  static crypto::tink::util::StatusOr<const EVP_MD *> EvpHash(
      HashType hash_type);

  // Validates whether 'sig_hash' is safe to use for digital signature.
  static crypto::tink::util::Status ValidateSignatureHash(
      subtle::HashType sig_hash);

  // Validates whether 'modulus_size' is at least 2048-bit.
  // To reach 128-bit security strength, RSA's modulus must be at least 3072-bit
  // while 2048-bit RSA key only has 112-bit security. Nevertheless, a 2048-bit
  // RSA key is considered safe by NIST until 2030 (see
  // https://www.keylength.com/en/4/).
  static crypto::tink::util::Status ValidateRsaModulusSize(size_t modulus_size);

  // Return an empty std::string if str.data() is nullptr; otherwise return str.
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
