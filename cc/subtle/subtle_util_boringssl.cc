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

#include "tink/subtle/subtle_util_boringssl.h"

#include <algorithm>
#include <iterator>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"
#include "absl/types/span.h"
#include "openssl/bn.h"
#include "openssl/cipher.h"
#include "openssl/curve25519.h"
#include "openssl/digest.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/mem.h"
#include "openssl/rsa.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

size_t ScalarSizeInBytes(const EC_GROUP *group) {
  return BN_num_bytes(EC_GROUP_get0_order(group));
}

size_t FieldElementSizeInBytes(const EC_GROUP *group) {
  unsigned degree_bits = EC_GROUP_get_degree(group);
  return (degree_bits + 7) / 8;
}

util::StatusOr<SubtleUtilBoringSSL::EcKey> EcKeyFromBoringEcKey(
    EllipticCurveType curve, const EC_KEY &key) {
  util::StatusOr<EC_GROUP *> group = SubtleUtilBoringSSL::GetEcGroup(curve);
  if (!group.ok()) {
    return group.status();
  }

  const BIGNUM *priv_key = EC_KEY_get0_private_key(&key);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(&key);
  internal::SslUniquePtr<BIGNUM> pub_key_x_bn(BN_new());
  internal::SslUniquePtr<BIGNUM> pub_key_y_bn(BN_new());
  if (!EC_POINT_get_affine_coordinates_GFp(*group, pub_key, pub_key_x_bn.get(),
                                           pub_key_y_bn.get(), nullptr)) {
    return util::Status(util::error::INTERNAL,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }
  SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = curve;
  util::StatusOr<std::string> pub_x_str = internal::BignumToString(
      pub_key_x_bn.get(), FieldElementSizeInBytes(*group));
  if (!pub_x_str.ok()) {
    return pub_x_str.status();
  }
  ec_key.pub_x = std::move(*pub_x_str);
  util::StatusOr<std::string> pub_y_str = internal::BignumToString(
      pub_key_y_bn.get(), FieldElementSizeInBytes(*group));
  if (!pub_y_str.ok()) {
    return pub_y_str.status();
  }
  ec_key.pub_y = std::move(*pub_y_str);
  util::StatusOr<util::SecretData> priv_key_or =
      internal::BignumToSecretData(priv_key, ScalarSizeInBytes(*group));
  if (!priv_key_or.ok()) {
    return priv_key_or.status();
  }
  ec_key.priv = std::move(*priv_key_or);
  return ec_key;
}

}  // namespace

// static
util::StatusOr<EC_GROUP *> SubtleUtilBoringSSL::GetEcGroup(
    EllipticCurveType curve_type) {
  switch (curve_type) {
    case EllipticCurveType::NIST_P256:
      return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    case EllipticCurveType::NIST_P384:
      return EC_GROUP_new_by_curve_name(NID_secp384r1);
    case EllipticCurveType::NIST_P521:
      return EC_GROUP_new_by_curve_name(NID_secp521r1);
    default:
      return util::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
}

// static
util::StatusOr<EllipticCurveType> SubtleUtilBoringSSL::GetCurve(
    const EC_GROUP *group) {
  switch (EC_GROUP_get_curve_name(group)) {
    case NID_X9_62_prime256v1:
      return EllipticCurveType::NIST_P256;
    case NID_secp384r1:
      return EllipticCurveType::NIST_P384;
    case NID_secp521r1:
      return EllipticCurveType::NIST_P521;
    default:
      return util::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
}

// static
util::StatusOr<EC_POINT *> SubtleUtilBoringSSL::GetEcPoint(
    EllipticCurveType curve, absl::string_view pubx, absl::string_view puby) {
  internal::SslUniquePtr<BIGNUM> bn_x(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(pubx.data()),
                pubx.size(), nullptr));
  internal::SslUniquePtr<BIGNUM> bn_y(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(puby.data()),
                puby.length(), nullptr));
  if (bn_x.get() == nullptr || bn_y.get() == nullptr) {
    return util::Status(util::error::INTERNAL, "BN_bin2bn failed");
  }
  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  internal::SslUniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
  internal::SslUniquePtr<EC_POINT> pub_key(EC_POINT_new(group.get()));
  if (1 != EC_POINT_set_affine_coordinates_GFp(
               group.get(), pub_key.get(), bn_x.get(), bn_y.get(), nullptr)) {
    return util::Status(util::error::INTERNAL,
                        "EC_POINT_set_affine_coordinates_GFp failed");
  }
  return pub_key.release();
}

// static
util::StatusOr<SubtleUtilBoringSSL::EcKey> SubtleUtilBoringSSL::GetNewEcKey(
    EllipticCurveType curve_type) {
  if (curve_type == EllipticCurveType::CURVE25519) {
    auto key = GenerateNewX25519Key();
    return EcKeyFromX25519Key(key.get());
  }
  auto status_or_group(SubtleUtilBoringSSL::GetEcGroup(curve_type));
  if (!status_or_group.ok()) return status_or_group.status();
  internal::SslUniquePtr<EC_GROUP> group(status_or_group.ValueOrDie());
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());

  if (key.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "EC key generation failed in BoringSSL.");
  }

  EC_KEY_set_group(key.get(), group.get());
  EC_KEY_generate_key(key.get());

  return EcKeyFromBoringEcKey(curve_type, *key);
}

// static
util::StatusOr<SubtleUtilBoringSSL::EcKey>
SubtleUtilBoringSSL::GetNewEcKeyFromSeed(EllipticCurveType curve_type,
                                         const util::SecretData &secret_seed) {
  // EC_KEY_derive_from_secret() is not defined in the version of BoringSSL
  // used when FIPS-only mode is enabled at compile time.
#ifdef TINK_USE_ONLY_FIPS
  return crypto::tink::util::Status(
      absl::StatusCode::kInternal,
      "Deriving EC keys is not allowed in FIPS mode.");
#else
  if (IsFipsModeEnabled()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        "Deriving EC keys is not allowed in FIPS mode.");
  }

  if (curve_type == EllipticCurveType::CURVE25519) {
    return util::Status(util::error::INTERNAL,
                        "Creating a X25519 key from a seed is not supported.");
  }

  util::StatusOr<EC_GROUP *> group =
      SubtleUtilBoringSSL::GetEcGroup(curve_type);
  if (!group.ok()) {
    return group.status();
  }

  internal::SslUniquePtr<EC_KEY> key(EC_KEY_derive_from_secret(
      *group, secret_seed.data(), secret_seed.size()));

  if (key.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "EC key generation failed in BoringSSL.");
  }

  return EcKeyFromBoringEcKey(curve_type, *key);
#endif
}

// static
std::unique_ptr<SubtleUtilBoringSSL::X25519Key>
SubtleUtilBoringSSL::GenerateNewX25519Key() {
  auto key = absl::make_unique<X25519Key>();
  X25519_keypair(key->public_value, key->private_key);

  return key;
}

// static
SubtleUtilBoringSSL::EcKey SubtleUtilBoringSSL::EcKeyFromX25519Key(
    const SubtleUtilBoringSSL::X25519Key *x25519_key) {
  SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = EllipticCurveType::CURVE25519;
  // Curve25519 public key is x, not (x,y).
  ec_key.pub_x =
      std::string(reinterpret_cast<const char *>(x25519_key->public_value),
                  X25519_PUBLIC_VALUE_LEN);
  ec_key.priv = util::SecretData(std::begin(x25519_key->private_key),
                                 std::end(x25519_key->private_key));
  return ec_key;
}

// static
util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::X25519Key>>
SubtleUtilBoringSSL::X25519KeyFromEcKey(
    const SubtleUtilBoringSSL::EcKey &ec_key) {
  auto x25519_key = absl::make_unique<SubtleUtilBoringSSL::X25519Key>();
  if (ec_key.curve != EllipticCurveType::CURVE25519) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "This key is not on curve 25519");
  }
  if (!ec_key.pub_y.empty()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Invalid X25519 key. pub_y is unexpectedly set.");
  }
  // Curve25519 public key is x, not (x,y).
  std::copy_n(ec_key.pub_x.begin(), X25519_PUBLIC_VALUE_LEN,
              std::begin(x25519_key->public_value));
  std::copy_n(ec_key.priv.begin(), X25519_PRIVATE_KEY_LEN,
              std::begin(x25519_key->private_key));
  return std::move(x25519_key);
}

// static
std::unique_ptr<SubtleUtilBoringSSL::Ed25519Key>
SubtleUtilBoringSSL::GetNewEd25519Key() {
  // Generate a new secret seed.
  util::SecretData secret_seed = util::SecretDataFromStringView(
      crypto::tink::subtle::Random::GetRandomBytes(32));
  return GetNewEd25519KeyFromSeed(secret_seed);
}

// static
std::unique_ptr<SubtleUtilBoringSSL::Ed25519Key>
SubtleUtilBoringSSL::GetNewEd25519KeyFromSeed(
    const util::SecretData &secret_seed) {
  // Generate a new key pair.
  uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t out_private_key[ED25519_PRIVATE_KEY_LEN];

  ED25519_keypair_from_seed(out_public_key, out_private_key,
                            secret_seed.data());

  auto key = absl::make_unique<Ed25519Key>();
  key->public_key = std::string(reinterpret_cast<const char *>(out_public_key),
                                ED25519_PUBLIC_KEY_LEN);
  std::string tmp = std::string(reinterpret_cast<const char *>(out_private_key),
                                ED25519_PRIVATE_KEY_LEN);
  // ED25519_keypair appends the public key at the end of the private key. Keep
  // the first 32 bytes that contain the private key and discard the public key.
  key->private_key = tmp.substr(0, 32);
  return key;
}

// static
util::StatusOr<const EVP_MD *> SubtleUtilBoringSSL::EvpHash(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return EVP_sha1();
    case HashType::SHA224:
      return EVP_sha224();
    case HashType::SHA256:
      return EVP_sha256();
    case HashType::SHA384:
      return EVP_sha384();
    case HashType::SHA512:
      return EVP_sha512();
    default:
      return util::Status(absl::StatusCode::kUnimplemented, "Unsupported hash");
  }
}

// static
util::StatusOr<util::SecretData> SubtleUtilBoringSSL::ComputeEcdhSharedSecret(
    EllipticCurveType curve, const BIGNUM *priv_key, const EC_POINT *pub_key) {
  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  internal::SslUniquePtr<EC_GROUP> priv_group(status_or_ec_group.ValueOrDie());
  internal::SslUniquePtr<EC_POINT> shared_point(EC_POINT_new(priv_group.get()));
  // BoringSSL's EC_POINT_set_affine_coordinates_GFp documentation says that
  // "unlike with OpenSSL, it's considered an error if the point is not on the
  // curve". To be sure, we double check here.
  if (1 != EC_POINT_is_on_curve(priv_group.get(), pub_key, nullptr)) {
    return util::Status(util::error::INTERNAL, "Point is not on curve");
  }
  // Compute the shared point.
  if (1 != EC_POINT_mul(priv_group.get(), shared_point.get(), nullptr, pub_key,
                        priv_key, nullptr)) {
    return util::Status(util::error::INTERNAL, "Point multiplication failed");
  }
  // Check for buggy computation.
  if (1 !=
      EC_POINT_is_on_curve(priv_group.get(), shared_point.get(), nullptr)) {
    return util::Status(util::error::INTERNAL, "Shared point is not on curve");
  }
  // Get shared point's x coordinate.
  internal::SslUniquePtr<BIGNUM> shared_x(BN_new());
  if (1 !=
      EC_POINT_get_affine_coordinates_GFp(priv_group.get(), shared_point.get(),
                                          shared_x.get(), nullptr, nullptr)) {
    return util::Status(util::error::INTERNAL,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }
  return internal::BignumToSecretData(
      shared_x.get(), FieldElementSizeInBytes(priv_group.get()));
}

// static
util::StatusOr<internal::SslUniquePtr<EC_POINT>>
SubtleUtilBoringSSL::EcPointDecode(EllipticCurveType curve,
                                   EcPointFormat format,
                                   absl::string_view encoded) {
  auto status_or_ec_group = GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  internal::SslUniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
  internal::SslUniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
  unsigned curve_size_in_bytes = (EC_GROUP_get_degree(group.get()) + 7) / 8;
  switch (format) {
    case EcPointFormat::UNCOMPRESSED: {
      if (static_cast<int>(encoded[0]) != 0x04) {
        return util::Status(
            util::error::INTERNAL,
            "Uncompressed point should start with 0x04, but input doesn't");
      }
      if (encoded.size() != 1 + 2 * curve_size_in_bytes) {
        return util::Status(
            util::error::INTERNAL,
            absl::Substitute("point has is $0 bytes, expected $1",
                             encoded.size(), 1 + 2 * curve_size_in_bytes));
      }
      if (1 !=
          EC_POINT_oct2point(group.get(), point.get(),
                             reinterpret_cast<const uint8_t *>(encoded.data()),
                             encoded.size(), nullptr)) {
        return util::Status(util::error::INTERNAL, "EC_POINT_toc2point failed");
      }
      break;
    }
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      if (encoded.size() != 2 * curve_size_in_bytes) {
        return util::Status(
            util::error::INTERNAL,
            absl::Substitute("point has is $0 bytes, expected $1",
                             encoded.size(), 2 * curve_size_in_bytes));
      }
      internal::SslUniquePtr<BIGNUM> x(BN_new());
      internal::SslUniquePtr<BIGNUM> y(BN_new());
      if (nullptr == x.get() || nullptr == y.get()) {
        return util::Status(
            util::error::INTERNAL,
            "Openssl internal error allocating memory for coordinates");
      }
      if (nullptr ==
          BN_bin2bn(reinterpret_cast<const uint8_t *>(encoded.data()),
                    curve_size_in_bytes, x.get())) {
        return util::Status(util::error::INTERNAL,
                            "Openssl internal error extracting x coordinate");
      }
      if (nullptr == BN_bin2bn(reinterpret_cast<const uint8_t *>(
                                   encoded.data() + curve_size_in_bytes),
                               curve_size_in_bytes, y.get())) {
        return util::Status(util::error::INTERNAL,
                            "Openssl internal error extracting y coordinate");
      }
      if (1 != EC_POINT_set_affine_coordinates_GFp(group.get(), point.get(),
                                                   x.get(), y.get(), nullptr)) {
        return util::Status(util::error::INTERNAL,
                            "Openssl internal error setting coordinates");
      }
      break;
    }
    case EcPointFormat::COMPRESSED: {
      if (static_cast<int>(encoded[0]) != 0x03 &&
          static_cast<int>(encoded[0]) != 0x02) {
        return util::Status(util::error::INTERNAL,
                            "Compressed point should start with either 0x02 or "
                            "0x03, but input doesn't");
      }
      if (1 !=
          EC_POINT_oct2point(group.get(), point.get(),
                             reinterpret_cast<const uint8_t *>(encoded.data()),
                             encoded.size(), nullptr)) {
        return util::Status(util::error::INTERNAL, "EC_POINT_oct2point failed");
      }
      break;
    }
    default:
      return util::Status(util::error::INTERNAL, "Unsupported format");
  }
  if (1 != EC_POINT_is_on_curve(group.get(), point.get(), nullptr)) {
    return util::Status(util::error::INTERNAL, "Point is not on curve");
  }
  return {std::move(point)};
}

// static
util::StatusOr<std::string> SubtleUtilBoringSSL::EcPointEncode(
    EllipticCurveType curve, EcPointFormat format, const EC_POINT *point) {
  auto status_or_ec_group = GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  internal::SslUniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
  unsigned curve_size_in_bytes = (EC_GROUP_get_degree(group.get()) + 7) / 8;
  if (1 != EC_POINT_is_on_curve(group.get(), point, nullptr)) {
    return util::Status(util::error::INTERNAL, "Point is not on curve");
  }

  switch (format) {
    case EcPointFormat::UNCOMPRESSED: {
      std::string encoded_point;
      const int encoded_point_size = 1 + 2 * curve_size_in_bytes;
      ResizeStringUninitialized(&encoded_point, encoded_point_size);
      size_t size =
          EC_POINT_point2oct(group.get(), point, POINT_CONVERSION_UNCOMPRESSED,
                             reinterpret_cast<uint8_t *>(&encoded_point[0]),
                             encoded_point_size, /*ctx=*/nullptr);
      if (size != encoded_point_size) {
        return util::Status(util::error::INTERNAL, "EC_POINT_point2oct failed");
      }
      return encoded_point;
    }
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      std::string encoded_point;
      internal::SslUniquePtr<BIGNUM> x(BN_new());
      internal::SslUniquePtr<BIGNUM> y(BN_new());
      if (nullptr == x.get() || nullptr == y.get()) {
        return util::Status(
            util::error::INTERNAL,
            "Openssl internal error allocating memory for coordinates");
      }
      ResizeStringUninitialized(&encoded_point, 2 * curve_size_in_bytes);

      if (1 != EC_POINT_get_affine_coordinates_GFp(group.get(), point, x.get(),
                                                   y.get(), nullptr)) {
        return util::Status(util::error::INTERNAL,
                            "Openssl internal error getting coordinates");
      }

      util::Status res = internal::BignumToBinaryPadded(
          absl::MakeSpan(&encoded_point[0], curve_size_in_bytes), x.get());

      if (!res.ok()) {
        return ToStatusF(
            util::error::INTERNAL,
            "Openssl internal error serializing the x coordinate - %s",
            res.message());
      }
      res = internal::BignumToBinaryPadded(
          absl::MakeSpan(&encoded_point[0] + curve_size_in_bytes,
                         curve_size_in_bytes),
          y.get());
      if (!res.ok()) {
        return ToStatusF(
            util::error::INTERNAL,
            "Openssl internal error serializing the y coordinate - %s",
            res.message());
      }
      return encoded_point;
    }
    case EcPointFormat::COMPRESSED: {
      std::string encoded_point;
      const int encoded_point_size = 1 + curve_size_in_bytes;
      ResizeStringUninitialized(&encoded_point, encoded_point_size);

      size_t size =
          EC_POINT_point2oct(group.get(), point, POINT_CONVERSION_COMPRESSED,
                             reinterpret_cast<uint8_t *>(&encoded_point[0]),
                             encoded_point_size, /*ctx=*/nullptr);
      if (size != encoded_point_size) {
        return util::Status(util::error::INTERNAL, "EC_POINT_point2oct failed");
      }
      return encoded_point;
    }
    default:
      return util::Status(util::error::INTERNAL, "Unsupported point format");
  }
}

// static
util::StatusOr<std::string> SubtleUtilBoringSSL::EcSignatureIeeeToDer(
    const EC_GROUP *group, absl::string_view ieee_sig) {
  size_t field_size_in_bytes = (EC_GROUP_get_degree(group) + 7) / 8;
  if (ieee_sig.size() != field_size_in_bytes * 2) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Signature is not valid.");
  }
  internal::SslUniquePtr<ECDSA_SIG> ecdsa(ECDSA_SIG_new());
  auto status_or_r =
      internal::StringToBignum(ieee_sig.substr(0, ieee_sig.size() / 2));
  if (!status_or_r.ok()) {
    return status_or_r.status();
  }
  auto status_or_s = internal::StringToBignum(
      ieee_sig.substr(ieee_sig.size() / 2, ieee_sig.size() / 2));
  if (!status_or_s.ok()) {
    return status_or_s.status();
  }
  if (1 != ECDSA_SIG_set0(ecdsa.get(), status_or_r.ValueOrDie().get(),
                          status_or_s.ValueOrDie().get())) {
    return util::Status(util::error::INTERNAL, "ECDSA_SIG_set0 error.");
  }
  // ECDSA_SIG_set0 takes ownership of s and r's pointers.
  status_or_r.ValueOrDie().release();
  status_or_s.ValueOrDie().release();
  uint8_t *der = nullptr;
  size_t der_len;
  if (!ECDSA_SIG_to_bytes(&der, &der_len, ecdsa.get())) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ECDSA_SIG_to_bytes error");
  }
  std::string result = std::string(reinterpret_cast<char *>(der), der_len);
  OPENSSL_free(der);
  return result;
}

// static
util::Status SubtleUtilBoringSSL::ValidateSignatureHash(HashType sig_hash) {
  switch (sig_hash) {
    case HashType::SHA256: /* fall through */
    case HashType::SHA384:
    case HashType::SHA512:
      return util::OkStatus();
    case HashType::SHA1: /* fall through */
    case HashType::SHA224:
      return util::Status(util::error::INVALID_ARGUMENT,
                          absl::StrCat("Hash function ", EnumToString(sig_hash),
                                       " is not safe for digital signature"));
    default:
      return util::Status(util::error::INVALID_ARGUMENT,
                          "Unsupported hash function");
  }
}

// static
util::Status SubtleUtilBoringSSL::ValidateRsaModulusSize(size_t modulus_size) {
  if (modulus_size < 2048) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrCat("Modulus size is ", modulus_size,
                     " only modulus size >= 2048-bit is supported"));
  }

  // In FIPS only mode we check here if the modulus is 3072, as this is the
  // only size which is covered by the FIPS validation and supported by Tink.
  // See
  // https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3318
  if (IsFipsModeEnabled() && (modulus_size != 3072)) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Modulus size is ", modulus_size,
                                     " only modulus size 3072 is supported "));
  }

  return util::OkStatus();
}

// static
util::Status SubtleUtilBoringSSL::ValidateRsaPublicExponent(
    absl::string_view exponent) {
  auto status_or_e = internal::StringToBignum(exponent);
  if (!status_or_e.ok()) return status_or_e.status();
  auto e = status_or_e.ValueOrDie().get();
  if (!BN_is_odd(e)) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Public exponent must be odd.");
  }

  if (BN_cmp_word(e, 65536) <= 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Public exponent must be greater than 65536.");
  }

  return util::OkStatus();
}

util::Status SubtleUtilBoringSSL::GetNewRsaKeyPair(
    int modulus_size_in_bits, const BIGNUM *e,
    SubtleUtilBoringSSL::RsaPrivateKey *private_key,
    SubtleUtilBoringSSL::RsaPublicKey *public_key) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa == nullptr) {
    return util::Status(util::error::INTERNAL, "Could not initialize RSA.");
  }

  internal::SslUniquePtr<BIGNUM> e_copy(BN_new());
  if (BN_copy(e_copy.get(), e) == nullptr) {
    return util::Status(util::error::INTERNAL, internal::GetSslErrors());
  }
  if (RSA_generate_key_ex(rsa.get(), modulus_size_in_bits, e_copy.get(),
                          /*cb=*/nullptr) != 1) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Error generating private key: ",
                                     internal::GetSslErrors()));
  }

  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);

  // Save exponents.
  util::StatusOr<std::string> n_str =
      internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  if (!n_str.ok()) {
    return n_str.status();
  }
  util::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  if (!e_str.ok()) {
    return e_str.status();
  }
  util::StatusOr<util::SecretData> d_str =
      internal::BignumToSecretData(d_bn, BN_num_bytes(d_bn));
  if (!d_str.ok()) {
    return d_str.status();
  }
  private_key->n = std::move(*n_str);
  private_key->e = std::move(*e_str);
  private_key->d = std::move(*d_str);
  public_key->n = private_key->n;
  public_key->e = private_key->e;

  // Save factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);
  util::StatusOr<util::SecretData> p_str =
      internal::BignumToSecretData(p_bn, BN_num_bytes(p_bn));
  if (!p_str.ok()) {
    return p_str.status();
  }
  util::StatusOr<util::SecretData> q_str =
      internal::BignumToSecretData(q_bn, BN_num_bytes(q_bn));
  if (!q_str.ok()) {
    return q_str.status();
  }
  private_key->p = std::move(*p_str);
  private_key->q = std::move(*q_str);

  // Save CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &crt_bn);
  util::StatusOr<util::SecretData> dp_str =
      internal::BignumToSecretData(dp_bn, BN_num_bytes(dp_bn));
  if (!dp_str.ok()) {
    return dp_str.status();
  }
  util::StatusOr<util::SecretData> dq_str =
      internal::BignumToSecretData(dq_bn, BN_num_bytes(dq_bn));
  if (!dq_str.ok()) {
    return dq_str.status();
  }
  util::StatusOr<util::SecretData> crt_str =
      internal::BignumToSecretData(crt_bn, BN_num_bytes(crt_bn));
  if (!crt_str.ok()) {
    return crt_str.status();
  }
  private_key->dp = std::move(*dp_str);
  private_key->dq = std::move(*dq_str);
  private_key->crt = std::move(*crt_str);

  return util::OkStatus();
}

// static
util::Status SubtleUtilBoringSSL::CopyKey(
    const SubtleUtilBoringSSL::RsaPrivateKey &key, RSA *rsa) {
  auto n = internal::StringToBignum(key.n);
  auto e = internal::StringToBignum(key.e);
  auto d = internal::StringToBignum(util::SecretDataAsStringView(key.d));
  if (!n.ok()) return n.status();
  if (!e.ok()) return e.status();
  if (!d.ok()) return d.status();
  if (RSA_set0_key(rsa, n.ValueOrDie().get(), e.ValueOrDie().get(),
                   d.ValueOrDie().get()) != 1) {
    return util::Status(
        util::error::INTERNAL,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  // The RSA object takes ownership when you call RSA_set0_key.
  n.ValueOrDie().release();
  e.ValueOrDie().release();
  d.ValueOrDie().release();
  return util::OkStatus();
}

// static
util::Status SubtleUtilBoringSSL::CopyPrimeFactors(
    const SubtleUtilBoringSSL::RsaPrivateKey &key, RSA *rsa) {
  auto p = internal::StringToBignum(util::SecretDataAsStringView(key.p));
  auto q = internal::StringToBignum(util::SecretDataAsStringView(key.q));
  if (!p.ok()) return p.status();
  if (!q.ok()) return q.status();
  if (RSA_set0_factors(rsa, p.ValueOrDie().get(), q.ValueOrDie().get()) != 1) {
    return util::Status(
        util::error::INTERNAL,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  p.ValueOrDie().release();
  q.ValueOrDie().release();
  return util::OkStatus();
}

// static
util::Status SubtleUtilBoringSSL::CopyCrtParams(
    const SubtleUtilBoringSSL::RsaPrivateKey &key, RSA *rsa) {
  auto dp = internal::StringToBignum(util::SecretDataAsStringView(key.dp));
  auto dq = internal::StringToBignum(util::SecretDataAsStringView(key.dq));
  auto crt = internal::StringToBignum(util::SecretDataAsStringView(key.crt));
  if (!dp.ok()) return dp.status();
  if (!dq.ok()) return dq.status();
  if (!crt.ok()) return crt.status();
  if (RSA_set0_crt_params(rsa, dp.ValueOrDie().get(), dq.ValueOrDie().get(),
                          crt.ValueOrDie().get()) != 1) {
    return util::Status(
        util::error::INTERNAL,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  dp.ValueOrDie().release();
  dq.ValueOrDie().release();
  crt.ValueOrDie().release();
  return util::OkStatus();
}

// static
util::StatusOr<internal::SslUniquePtr<RSA>>
SubtleUtilBoringSSL::BoringSslRsaFromRsaPrivateKey(
    const SubtleUtilBoringSSL::RsaPrivateKey &rsa_key) {
  auto status_or_n = internal::StringToBignum(rsa_key.n);
  if (!status_or_n.ok()) {
    return status_or_n.status();
  }

  auto modulus_status = SubtleUtilBoringSSL::ValidateRsaModulusSize(
      BN_num_bits(status_or_n.ValueOrDie().get()));
  if (!modulus_status.ok()) {
    return modulus_status;
  }

  // Check RSA's public exponent
  auto exponent_status =
      SubtleUtilBoringSSL::ValidateRsaPublicExponent(rsa_key.e);
  if (!exponent_status.ok()) return exponent_status;

  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "BoringSsl RSA allocation error");
  }
  util::Status status = SubtleUtilBoringSSL::CopyKey(rsa_key, rsa.get());
  if (!status.ok()) {
    return status;
  }

  status = SubtleUtilBoringSSL::CopyPrimeFactors(rsa_key, rsa.get());
  if (!status.ok()) {
    return status;
  }

  status = SubtleUtilBoringSSL::CopyCrtParams(rsa_key, rsa.get());
  if (!status.ok()) {
    return status;
  }

  if (RSA_check_key(rsa.get()) == 0 || RSA_check_fips(rsa.get()) == 0) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }

  return rsa;
}

// static
util::StatusOr<internal::SslUniquePtr<RSA>>
SubtleUtilBoringSSL::BoringSslRsaFromRsaPublicKey(
    const SubtleUtilBoringSSL::RsaPublicKey &key) {
  auto status_or_n = internal::StringToBignum(key.n);
  if (!status_or_n.ok()) {
    return status_or_n.status();
  }

  auto status_or_e = internal::StringToBignum(key.e);
  if (!status_or_e.ok()) {
    return status_or_e.status();
  }

  auto modulus_status = SubtleUtilBoringSSL::ValidateRsaModulusSize(
      BN_num_bits(status_or_n.ValueOrDie().get()));
  if (!modulus_status.ok()) {
    return modulus_status;
  }

  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "BoringSsl RSA allocation error");
  }

  // The value d is null for a public RSA key.
  if (1 != RSA_set0_key(rsa.get(), status_or_n.ValueOrDie().get(),
                        status_or_e.ValueOrDie().get(), /*d=*/nullptr)) {
    return util::Status(util::error::INTERNAL, "Could not set RSA key.");
  }
  status_or_n.ValueOrDie().release();
  status_or_e.ValueOrDie().release();

  return rsa;
}

const EVP_CIPHER *SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(
    uint32_t size_in_bytes) {
  util::StatusOr<const EVP_CIPHER *> res =
      internal::GetAesCtrCipherForKeySize(size_in_bytes);
  if (!res.ok()) {
    return nullptr;
  }
  return *res;
}

const EVP_CIPHER *SubtleUtilBoringSSL::GetAesGcmCipherForKeySize(
    uint32_t size_in_bytes) {
  util::StatusOr<const EVP_CIPHER *> res =
      internal::GetAesGcmCipherForKeySize(size_in_bytes);
  if (!res.ok()) {
    return nullptr;
  }
  return *res;
}

#ifdef OPENSSL_IS_BORINGSSL
const EVP_AEAD *SubtleUtilBoringSSL::GetAesGcmAeadForKeySize(
    uint32_t size_in_bytes) {
  util::StatusOr<const EVP_AEAD *> res =
      internal::GetAesGcmAeadForKeySize(size_in_bytes);
  if (!res.ok()) {
    return nullptr;
  }
  return *res;
}
#endif

namespace boringssl {

util::StatusOr<std::vector<uint8_t>> ComputeHash(absl::string_view input,
                                                 const EVP_MD &hasher) {
  input = internal::EnsureStringNonNull(input);
  std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
  uint32_t digest_length = 0;
  if (EVP_Digest(input.data(), input.length(), digest.data(), &digest_length,
                 &hasher, /*impl=*/nullptr) != 1) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Openssl internal error computing hash: ",
                                     internal::GetSslErrors()));
  }
  digest.resize(digest_length);
  return digest;
}

}  // namespace boringssl

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
