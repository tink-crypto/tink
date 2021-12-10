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
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"
#include "absl/types/span.h"
#include "openssl/base.h"
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
#include "tink/internal/ec_util.h"
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
  util::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }

  const BIGNUM *priv_key = EC_KEY_get0_private_key(&key);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(&key);
  internal::SslUniquePtr<BIGNUM> pub_key_x_bn(BN_new());
  internal::SslUniquePtr<BIGNUM> pub_key_y_bn(BN_new());
  if (!EC_POINT_get_affine_coordinates_GFp(group->get(), pub_key,
                                           pub_key_x_bn.get(),
                                           pub_key_y_bn.get(), nullptr)) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }
  SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = curve;
  util::StatusOr<std::string> pub_x_str = internal::BignumToString(
      pub_key_x_bn.get(), FieldElementSizeInBytes(group->get()));
  if (!pub_x_str.ok()) {
    return pub_x_str.status();
  }
  ec_key.pub_x = std::move(*pub_x_str);
  util::StatusOr<std::string> pub_y_str = internal::BignumToString(
      pub_key_y_bn.get(), FieldElementSizeInBytes(group->get()));
  if (!pub_y_str.ok()) {
    return pub_y_str.status();
  }
  ec_key.pub_y = std::move(*pub_y_str);
  util::StatusOr<util::SecretData> priv_key_or =
      internal::BignumToSecretData(priv_key, ScalarSizeInBytes(group->get()));
  if (!priv_key_or.ok()) {
    return priv_key_or.status();
  }
  ec_key.priv = std::move(*priv_key_or);
  return ec_key;
}

}  // namespace

// static
util::StatusOr<SubtleUtilBoringSSL::EcKey> SubtleUtilBoringSSL::GetNewEcKey(
    EllipticCurveType curve_type) {
  if (curve_type == EllipticCurveType::CURVE25519) {
    auto key = GenerateNewX25519Key();
    return EcKeyFromX25519Key(key.get());
  }
  util::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(curve_type);
  if (!group.ok()) {
    return group.status();
  }
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());

  if (key.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC key generation failed in BoringSSL.");
  }

  EC_KEY_set_group(key.get(), group->get());
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
    return util::Status(absl::StatusCode::kInternal,
                        "Creating a X25519 key from a seed is not supported.");
  }

  util::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(curve_type);
  if (!group.ok()) {
    return group.status();
  }

  internal::SslUniquePtr<EC_KEY> key(EC_KEY_derive_from_secret(
      group->get(), secret_seed.data(), secret_seed.size()));

  if (key.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC key generation failed in BoringSSL.");
  }

  return EcKeyFromBoringEcKey(curve_type, *key);
#endif
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
  util::StatusOr<internal::SslUniquePtr<EC_GROUP>> priv_group =
      internal::EcGroupFromCurveType(curve);
  if (!priv_group.ok()) {
    return priv_group.status();
  }
  internal::SslUniquePtr<EC_POINT> shared_point(
      EC_POINT_new(priv_group->get()));
  // BoringSSL's EC_POINT_set_affine_coordinates_GFp documentation says that
  // "unlike with OpenSSL, it's considered an error if the point is not on the
  // curve". To be sure, we double check here.
  if (1 != EC_POINT_is_on_curve(priv_group->get(), pub_key, nullptr)) {
    return util::Status(absl::StatusCode::kInternal, "Point is not on curve");
  }
  // Compute the shared point.
  if (1 != EC_POINT_mul(priv_group->get(), shared_point.get(), nullptr, pub_key,
                        priv_key, nullptr)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Point multiplication failed");
  }
  // Check for buggy computation.
  if (1 !=
      EC_POINT_is_on_curve(priv_group->get(), shared_point.get(), nullptr)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Shared point is not on curve");
  }
  // Get shared point's x coordinate.
  internal::SslUniquePtr<BIGNUM> shared_x(BN_new());
  if (1 !=
      EC_POINT_get_affine_coordinates_GFp(priv_group->get(), shared_point.get(),
                                          shared_x.get(), nullptr, nullptr)) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }
  return internal::BignumToSecretData(
      shared_x.get(), FieldElementSizeInBytes(priv_group->get()));
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
            absl::StatusCode::kInternal,
            "Uncompressed point should start with 0x04, but input doesn't");
      }
      if (encoded.size() != 1 + 2 * curve_size_in_bytes) {
        return util::Status(
            absl::StatusCode::kInternal,
            absl::Substitute("point has is $0 bytes, expected $1",
                             encoded.size(), 1 + 2 * curve_size_in_bytes));
      }
      if (1 !=
          EC_POINT_oct2point(group.get(), point.get(),
                             reinterpret_cast<const uint8_t *>(encoded.data()),
                             encoded.size(), nullptr)) {
        return util::Status(absl::StatusCode::kInternal,
                            "EC_POINT_toc2point failed");
      }
      break;
    }
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      if (encoded.size() != 2 * curve_size_in_bytes) {
        return util::Status(
            absl::StatusCode::kInternal,
            absl::Substitute("point has is $0 bytes, expected $1",
                             encoded.size(), 2 * curve_size_in_bytes));
      }
      internal::SslUniquePtr<BIGNUM> x(BN_new());
      internal::SslUniquePtr<BIGNUM> y(BN_new());
      if (nullptr == x.get() || nullptr == y.get()) {
        return util::Status(
            absl::StatusCode::kInternal,
            "Openssl internal error allocating memory for coordinates");
      }
      if (nullptr ==
          BN_bin2bn(reinterpret_cast<const uint8_t *>(encoded.data()),
                    curve_size_in_bytes, x.get())) {
        return util::Status(absl::StatusCode::kInternal,
                            "Openssl internal error extracting x coordinate");
      }
      if (nullptr == BN_bin2bn(reinterpret_cast<const uint8_t *>(
                                   encoded.data() + curve_size_in_bytes),
                               curve_size_in_bytes, y.get())) {
        return util::Status(absl::StatusCode::kInternal,
                            "Openssl internal error extracting y coordinate");
      }
      if (1 != EC_POINT_set_affine_coordinates_GFp(group.get(), point.get(),
                                                   x.get(), y.get(), nullptr)) {
        return util::Status(absl::StatusCode::kInternal,
                            "Openssl internal error setting coordinates");
      }
      break;
    }
    case EcPointFormat::COMPRESSED: {
      if (static_cast<int>(encoded[0]) != 0x03 &&
          static_cast<int>(encoded[0]) != 0x02) {
        return util::Status(absl::StatusCode::kInternal,
                            "Compressed point should start with either 0x02 or "
                            "0x03, but input doesn't");
      }
      if (1 !=
          EC_POINT_oct2point(group.get(), point.get(),
                             reinterpret_cast<const uint8_t *>(encoded.data()),
                             encoded.size(), nullptr)) {
        return util::Status(absl::StatusCode::kInternal,
                            "EC_POINT_oct2point failed");
      }
      break;
    }
    default:
      return util::Status(absl::StatusCode::kInternal, "Unsupported format");
  }
  if (1 != EC_POINT_is_on_curve(group.get(), point.get(), nullptr)) {
    return util::Status(absl::StatusCode::kInternal, "Point is not on curve");
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
    return util::Status(absl::StatusCode::kInternal, "Point is not on curve");
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
        return util::Status(absl::StatusCode::kInternal,
                            "EC_POINT_point2oct failed");
      }
      return encoded_point;
    }
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      std::string encoded_point;
      internal::SslUniquePtr<BIGNUM> x(BN_new());
      internal::SslUniquePtr<BIGNUM> y(BN_new());
      if (nullptr == x.get() || nullptr == y.get()) {
        return util::Status(
            absl::StatusCode::kInternal,
            "Openssl internal error allocating memory for coordinates");
      }
      ResizeStringUninitialized(&encoded_point, 2 * curve_size_in_bytes);

      if (1 != EC_POINT_get_affine_coordinates_GFp(group.get(), point, x.get(),
                                                   y.get(), nullptr)) {
        return util::Status(absl::StatusCode::kInternal,
                            "Openssl internal error getting coordinates");
      }

      util::Status res = internal::BignumToBinaryPadded(
          absl::MakeSpan(&encoded_point[0], curve_size_in_bytes), x.get());

      if (!res.ok()) {
        return ToStatusF(
            absl::StatusCode::kInternal,
            "Openssl internal error serializing the x coordinate - %s",
            res.message());
      }
      res = internal::BignumToBinaryPadded(
          absl::MakeSpan(&encoded_point[0] + curve_size_in_bytes,
                         curve_size_in_bytes),
          y.get());
      if (!res.ok()) {
        return ToStatusF(
            absl::StatusCode::kInternal,
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
        return util::Status(absl::StatusCode::kInternal,
                            "EC_POINT_point2oct failed");
      }
      return encoded_point;
    }
    default:
      return util::Status(absl::StatusCode::kInternal,
                          "Unsupported point format");
  }
}

// static
util::StatusOr<std::string> SubtleUtilBoringSSL::EcSignatureIeeeToDer(
    const EC_GROUP *group, absl::string_view ieee_sig) {
  size_t field_size_in_bytes = (EC_GROUP_get_degree(group) + 7) / 8;
  if (ieee_sig.size() != field_size_in_bytes * 2) {
    return util::Status(absl::StatusCode::kInvalidArgument,
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
    return util::Status(absl::StatusCode::kInternal, "ECDSA_SIG_set0 error.");
  }
  // ECDSA_SIG_set0 takes ownership of s and r's pointers.
  status_or_r.ValueOrDie().release();
  status_or_s.ValueOrDie().release();
  uint8_t *der = nullptr;
  size_t der_len;
  if (!ECDSA_SIG_to_bytes(&der, &der_len, ecdsa.get())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
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
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Hash function ", EnumToString(sig_hash),
                                       " is not safe for digital signature"));
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported hash function");
  }
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
    return util::Status(absl::StatusCode::kInternal,
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
