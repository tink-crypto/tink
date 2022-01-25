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
#include "tink/internal/ec_util.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::EcPointFormat;
using ::crypto::tink::subtle::EllipticCurveType;

// Encodes the given `point` to string, according to a `conversion_form`.
util::StatusOr<std::string> SslEcPointEncode(
    EC_GROUP *group, const EC_POINT *point,
    point_conversion_form_t conversion_form) {
  // Get the buffer size first passing a NULL buffer.
  size_t buffer_size =
      EC_POINT_point2oct(group, point, conversion_form,
                         /*buf=*/nullptr, /*len=*/0, /*ctx=*/nullptr);
  if (buffer_size == 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_POINT_point2oct failed");
  }

  std::string encoded_point;
  subtle::ResizeStringUninitialized(&encoded_point, buffer_size);
  size_t size =
      EC_POINT_point2oct(group, point, conversion_form,
                         reinterpret_cast<uint8_t *>(&encoded_point[0]),
                         buffer_size, /*ctx=*/nullptr);
  if (size == 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_POINT_point2oct failed");
  }
  return encoded_point;
}

// Returns an EC_POINT from `group`, and encoded (bigendian string
// representation of BIGNUMs) point coordinates `pubx`, `puby`.
util::StatusOr<SslUniquePtr<EC_POINT>> SslGetEcPointFromCoordinates(
    const EC_GROUP *group, absl::string_view pubx, absl::string_view puby) {
  util::StatusOr<SslUniquePtr<BIGNUM>> bn_x = StringToBignum(pubx);
  if (!bn_x.ok()) {
    return bn_x.status();
  }
  util::StatusOr<SslUniquePtr<BIGNUM>> bn_y = StringToBignum(puby);
  if (!bn_y.ok()) {
    return bn_y.status();
  }
  SslUniquePtr<EC_POINT> pub_key(EC_POINT_new(group));
  // In BoringSSL and OpenSSL > 1.1.0 EC_POINT_set_affine_coordinates_GFp
  // already checkes if the point is on the curve.
  if (EC_POINT_set_affine_coordinates_GFp(group, pub_key.get(), bn_x->get(),
                                          bn_y->get(), nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_POINT_set_affine_coordinates_GFp failed");
  }
  return std::move(pub_key);
}

// Returns an EC_POINT from an `encoded` point with format `format` and curve
// type `curve`. `format` is either COMPRESSED or UNCOMPRESSED.
util::StatusOr<SslUniquePtr<EC_POINT>> SslGetEcPointFromEncoded(
    EllipticCurveType curve, EcPointFormat format, absl::string_view encoded) {
  if (format != EcPointFormat::UNCOMPRESSED &&
      format != EcPointFormat::COMPRESSED) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid format ", subtle::EnumToString(format)));
  }
  util::StatusOr<SslUniquePtr<EC_GROUP>> group = EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }

  util::StatusOr<int32_t> encoding_size =
      EcPointEncodingSizeInBytes(curve, format);
  if (!encoding_size.ok()) {
    return encoding_size.status();
  }
  if (encoded.size() != *encoding_size) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Encoded point's size is ", encoded.size(),
                                     " bytes; expected ", *encoding_size));
  }

  // Check starting byte.
  if (format == EcPointFormat::UNCOMPRESSED &&
      static_cast<int>(encoded[0]) != 0x04) {
    return util::Status(
        absl::StatusCode::kInternal,
        "Uncompressed point should start with 0x04, but input doesn't");
  } else if (format == EcPointFormat::COMPRESSED &&
             static_cast<int>(encoded[0]) != 0x03 &&
             static_cast<int>(encoded[0]) != 0x02) {
    return util::Status(absl::StatusCode::kInternal,
                        "Compressed point should start with either 0x02 or "
                        "0x03, but input doesn't");
  }

  SslUniquePtr<EC_POINT> point(EC_POINT_new(group->get()));
  if (EC_POINT_oct2point(group->get(), point.get(),
                         reinterpret_cast<const uint8_t *>(encoded.data()),
                         encoded.size(), nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_POINT_toc2point failed");
  }
  // Check that point is on curve.
  if (EC_POINT_is_on_curve(group->get(), point.get(), nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal, "Point is not on curve");
  }

  return std::move(point);
}

// OpenSSL/BoringSSL's EC_POINT as a pair of BIGNUMs.
struct EcPointCoordinates {
  SslUniquePtr<BIGNUM> x;
  SslUniquePtr<BIGNUM> y;
};

// Returns a given `point` as a pair of BIGNUMs. Precondition: `group` and
// `point` are not null.
util::StatusOr<EcPointCoordinates> SslGetEcPointCoordinates(
    const EC_GROUP *group, const EC_POINT *point) {
  EcPointCoordinates coordinates = {
      SslUniquePtr<BIGNUM>(BN_new()),
      SslUniquePtr<BIGNUM>(BN_new()),
  };
  if (coordinates.x == nullptr || coordinates.y == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Unable to allocate memory for the point coordinates");
  }
  if (EC_POINT_get_affine_coordinates_GFp(group, point, coordinates.x.get(),
                                          coordinates.y.get(), nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }
  return std::move(coordinates);
}

size_t ScalarSizeInBytes(const EC_GROUP *group) {
  return BN_num_bytes(EC_GROUP_get0_order(group));
}

size_t SslEcFieldSizeInBytes(const EC_GROUP *group) {
  unsigned degree_bits = EC_GROUP_get_degree(group);
  return (degree_bits + 7) / 8;
}

// Given an OpenSSL/BoringSSL key EC_KEY `key` and curve type `curve` return an
// EcKey.
util::StatusOr<EcKey> EcKeyFromSslEcKey(EllipticCurveType curve,
                                        const EC_KEY &key) {
  util::StatusOr<SslUniquePtr<EC_GROUP>> group = EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }
  const BIGNUM *priv_key = EC_KEY_get0_private_key(&key);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(&key);

  util::StatusOr<EcPointCoordinates> pub_key_bns =
      SslGetEcPointCoordinates(group->get(), pub_key);
  if (!pub_key_bns.ok()) {
    return pub_key_bns.status();
  }

  const int kFieldElementSizeInBytes = SslEcFieldSizeInBytes(group->get());

  util::StatusOr<std::string> pub_x_str =
      BignumToString(pub_key_bns->x.get(), kFieldElementSizeInBytes);
  if (!pub_x_str.ok()) {
    return pub_x_str.status();
  }
  util::StatusOr<std::string> pub_y_str =
      BignumToString(pub_key_bns->y.get(), kFieldElementSizeInBytes);
  if (!pub_y_str.ok()) {
    return pub_y_str.status();
  }
  util::StatusOr<util::SecretData> priv_key_data =
      BignumToSecretData(priv_key, ScalarSizeInBytes(group->get()));
  if (!priv_key_data.ok()) {
    return priv_key_data.status();
  }
  EcKey ec_key = {
      /*curve=*/curve,
      /*pub_x=*/*std::move(pub_x_str),
      /*pub_y=*/*std::move(pub_y_str),
      /*priv=*/*std::move(priv_key_data),
  };
  return ec_key;
}

enum SslEvpPkeyType {
  kX25519Key = EVP_PKEY_X25519,
  kEd25519Key = EVP_PKEY_ED25519
};

// Returns a new EVP_PKEY key from the given `key_type`.
util::StatusOr<SslUniquePtr<EVP_PKEY>> SslNewEvpKey(SslEvpPkeyType key_type) {
  EVP_PKEY *private_key = nullptr;
  SslUniquePtr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new_id(key_type, /*e=*/nullptr));
  if (pctx == nullptr) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("EVP_PKEY_CTX_new_id failed for id ", key_type));
  }

  if (EVP_PKEY_keygen_init(pctx.get()) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_keygen_init failed");
  }
  if (EVP_PKEY_keygen(pctx.get(), &private_key) != 1) {
    return util::Status(absl::StatusCode::kInternal, "EVP_PKEY_keygen failed");
  }
  return {SslUniquePtr<EVP_PKEY>(private_key)};
}

// Given a private EVP_PKEY `evp_key` of key type `key_type` fills `priv_key`
// and `pub_key` with raw private and public keys, respectively.
util::Status SslNewKeyPairFromEcKey(SslEvpPkeyType key_type,
                                    const EVP_PKEY &evp_key,
                                    absl::Span<uint8_t> priv_key,
                                    absl::Span<uint8_t> pub_key) {
  size_t len = priv_key.size();
  if (EVP_PKEY_get_raw_private_key(&evp_key, priv_key.data(), &len) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_get_raw_private_key failed");
  }
  if (len != priv_key.size()) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Invalid private key size; expected ",
                                     priv_key.size(), " got ", len));
  }

  len = pub_key.size();
  if (EVP_PKEY_get_raw_public_key(&evp_key, pub_key.data(), &len) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_get_raw_public_key failed");
  }
  if (len != pub_key.size()) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Invalid public key size; expected ",
                                     pub_key.size(), " got ", len));
  }

  return util::OkStatus();
}

util::StatusOr<std::string> SslEcdsaSignatureToBytes(
    const ECDSA_SIG *ecdsa_signature) {
  if (ecdsa_signature == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ECDSA signature is null");
  }
  uint8_t *der = nullptr;
  int der_len = i2d_ECDSA_SIG(ecdsa_signature, &der);
  if (der_len <= 0) {
    return util::Status(absl::StatusCode::kInternal, "i2d_ECDSA_SIG failed");
  }
  auto result = std::string(reinterpret_cast<char *>(der), der_len);
  OPENSSL_free(der);
  return result;
}

}  // namespace

util::StatusOr<int32_t> EcFieldSizeInBytes(EllipticCurveType curve_type) {
  if (curve_type == EllipticCurveType::CURVE25519) {
    return 32;
  }
  util::StatusOr<SslUniquePtr<EC_GROUP>> ec_group =
      EcGroupFromCurveType(curve_type);
  if (!ec_group.ok()) {
    return ec_group.status();
  }
  return SslEcFieldSizeInBytes(ec_group->get());
}

util::StatusOr<int32_t> EcPointEncodingSizeInBytes(EllipticCurveType curve_type,
                                                   EcPointFormat point_format) {
  util::StatusOr<int32_t> coordinate_size = EcFieldSizeInBytes(curve_type);
  if (!coordinate_size.ok()) {
    return coordinate_size.status();
  }
  if (curve_type == EllipticCurveType::CURVE25519) {
    return coordinate_size;
  }
  if (*coordinate_size == 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Unsupported elliptic curve type: ",
                                     EnumToString(curve_type)));
  }
  switch (point_format) {
    case EcPointFormat::UNCOMPRESSED:
      return 2 * (*coordinate_size) + 1;
    case EcPointFormat::COMPRESSED:
      return (*coordinate_size) + 1;
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
      return 2 * (*coordinate_size);
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported elliptic curve point format: ",
                       EnumToString(point_format)));
  }
}

util::StatusOr<EcKey> NewEcKey(EllipticCurveType curve_type) {
  if (curve_type == EllipticCurveType::CURVE25519) {
    util::StatusOr<std::unique_ptr<X25519Key>> key = NewX25519Key();
    if (!key.ok()) {
      return key.status();
    }
    return EcKeyFromX25519Key(key->get());
  }
  util::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(curve_type);
  if (!group.ok()) {
    return group.status();
  }
  SslUniquePtr<EC_KEY> key(EC_KEY_new());

  if (key.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal, "EC_KEY_new failed");
  }
  EC_KEY_set_group(key.get(), group->get());
  EC_KEY_generate_key(key.get());
  return EcKeyFromSslEcKey(curve_type, *key);
}

util::StatusOr<EcKey> NewEcKey(EllipticCurveType curve_type,
                               const util::SecretData &secret_seed) {
  // EC_KEY_derive_from_secret() is neither defined in the version of BoringSSL
  // used when FIPS-only mode is enabled at compile time, nor currently
  // implemented for OpenSSL.
#if defined(TINK_USE_ONLY_FIPS)
  return util::Status(
      absl::StatusCode::kUnimplemented,
      "Deriving EC keys from a secret seed is not allowed in FIPS mode");
#elif !defined(OPENSSL_IS_BORINGSSL)
  return util::Status(
      absl::StatusCode::kUnimplemented,
      "Deriving EC keys from a secret seed is not supported with OpenSSL");
#else
  if (IsFipsModeEnabled()) {
    return util::Status(
        absl::StatusCode::kInternal,
        "Deriving EC keys from a secret seed is not allowed in FIPS mode");
  }
  if (curve_type == EllipticCurveType::CURVE25519) {
    return util::Status(
        absl::StatusCode::kInternal,
        "Creating a X25519 key from a secret seed is not supported");
  }
  util::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(curve_type);
  if (!group.ok()) {
    return group.status();
  }
  SslUniquePtr<EC_KEY> key(EC_KEY_derive_from_secret(
      group->get(), secret_seed.data(), secret_seed.size()));
  if (key.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_KEY_derive_from_secret failed");
  }
  return EcKeyFromSslEcKey(curve_type, *key);
#endif
}

util::StatusOr<std::unique_ptr<X25519Key>> NewX25519Key() {
  util::StatusOr<SslUniquePtr<EVP_PKEY>> private_key =
      SslNewEvpKey(SslEvpPkeyType::kX25519Key);
  if (!private_key.ok()) {
    return private_key.status();
  }

  auto key = absl::make_unique<X25519Key>();
  util::Status res = SslNewKeyPairFromEcKey(
      SslEvpPkeyType::kX25519Key, **private_key,
      absl::MakeSpan(key->private_key, X25519KeyPrivKeySize()),
      absl::MakeSpan(key->public_value, X25519KeyPubKeySize()));
  if (!res.ok()) {
    return res;
  }
  return key;
}

EcKey EcKeyFromX25519Key(const X25519Key *x25519_key) {
  EcKey ec_key;
  ec_key.curve = subtle::EllipticCurveType::CURVE25519;
  // Curve25519 public key is x, not (x,y).
  ec_key.pub_x =
      std::string(reinterpret_cast<const char *>(x25519_key->public_value),
                  X25519KeyPubKeySize());
  ec_key.priv = util::SecretData(std::begin(x25519_key->private_key),
                                 std::end(x25519_key->private_key));
  return ec_key;
}

util::StatusOr<std::unique_ptr<Ed25519Key>> NewEd25519Key() {
  util::SecretData seed =
      subtle::Random::GetRandomKeyBytes(Ed25519KeyPrivKeySize());
  return NewEd25519Key(seed);
}

util::StatusOr<std::unique_ptr<Ed25519Key>> NewEd25519Key(
    const util::SecretData &secret_seed) {
  if (secret_seed.size() != Ed25519KeyPrivKeySize()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid seed of length ", secret_seed.size(),
                     "; expected ", Ed25519KeyPrivKeySize()));
  }

  // In BoringSSL this calls ED25519_keypair_from_seed. Accessing the public key
  // with EVP_PKEY_get_raw_public_key returns the last 32 bytes of the private
  // key stored by BoringSSL.
  SslUniquePtr<EVP_PKEY> priv_key(EVP_PKEY_new_raw_private_key(
      SslEvpPkeyType::kEd25519Key, nullptr, secret_seed.data(),
      Ed25519KeyPrivKeySize()));
  if (priv_key == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_new_raw_private_key failed");
  }

  auto key = absl::make_unique<Ed25519Key>();
  subtle::ResizeStringUninitialized(&key->private_key, Ed25519KeyPrivKeySize());
  subtle::ResizeStringUninitialized(&key->public_key, Ed25519KeyPubKeySize());
  uint8_t *priv_key_ptr = reinterpret_cast<uint8_t *>(&key->private_key[0]);
  uint8_t *pub_key_ptr = reinterpret_cast<uint8_t *>(&key->public_key[0]);
  // The EVP_PKEY interface returns only the first 32 bytes of the private key.
  util::Status res = SslNewKeyPairFromEcKey(
      SslEvpPkeyType::kEd25519Key, *priv_key,
      absl::MakeSpan(priv_key_ptr, Ed25519KeyPrivKeySize()),
      absl::MakeSpan(pub_key_ptr, Ed25519KeyPubKeySize()));
  if (!res.ok()) {
    return res;
  }
  return std::move(key);
}

util::StatusOr<std::unique_ptr<X25519Key>> X25519KeyFromEcKey(
    const EcKey &ec_key) {
  auto x25519_key = absl::make_unique<X25519Key>();
  if (ec_key.curve != subtle::EllipticCurveType::CURVE25519) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "This key is not on curve 25519");
  }
  if (!ec_key.pub_y.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid X25519 key. pub_y is unexpectedly set.");
  }
  // Curve25519 public key is x, not (x,y).
  std::copy_n(ec_key.pub_x.begin(), X25519KeyPubKeySize(),
              std::begin(x25519_key->public_value));
  std::copy_n(ec_key.priv.begin(), X25519KeyPrivKeySize(),
              std::begin(x25519_key->private_key));
  return std::move(x25519_key);
}

util::StatusOr<util::SecretData> ComputeX25519SharedSecret(
    EVP_PKEY *private_key, EVP_PKEY *peer_public_key) {
  // Make sure the keys are actually X25519 keys.
  if (EVP_PKEY_id(private_key) != SslEvpPkeyType::kX25519Key) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid type for private key");
  }
  if (EVP_PKEY_id(peer_public_key) != SslEvpPkeyType::kX25519Key) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid type for peer's public key");
  }

  internal::SslUniquePtr<EVP_PKEY_CTX> pctx(
      EVP_PKEY_CTX_new(private_key, nullptr));
  util::SecretData shared_secret(internal::X25519KeySharedKeySize());
  size_t out_key_length = shared_secret.size();
  if (EVP_PKEY_derive_init(pctx.get()) <= 0 ||
      EVP_PKEY_derive_set_peer(pctx.get(), peer_public_key) <= 0 ||
      EVP_PKEY_derive(pctx.get(), shared_secret.data(), &out_key_length) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "Secret generation failed");
  }
  return shared_secret;
}

util::StatusOr<std::string> EcPointEncode(EllipticCurveType curve,
                                          EcPointFormat format,
                                          const EC_POINT *point) {
  util::StatusOr<SslUniquePtr<EC_GROUP>> group = EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }
  if (EC_POINT_is_on_curve(group->get(), point, nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal, "Point is not on curve");
  }
  switch (format) {
    case EcPointFormat::UNCOMPRESSED: {
      return SslEcPointEncode(group->get(), point,
                              POINT_CONVERSION_UNCOMPRESSED);
    }
    case EcPointFormat::COMPRESSED: {
      return SslEcPointEncode(group->get(), point, POINT_CONVERSION_COMPRESSED);
    }
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      util::StatusOr<EcPointCoordinates> ec_point_xy =
          SslGetEcPointCoordinates(group->get(), point);
      if (!ec_point_xy.ok()) {
        return ec_point_xy.status();
      }
      const int kCurveSizeInBytes = SslEcFieldSizeInBytes(group->get());
      std::string encoded_point;
      subtle::ResizeStringUninitialized(&encoded_point, 2 * kCurveSizeInBytes);
      util::Status res = BignumToBinaryPadded(
          absl::MakeSpan(&encoded_point[0], kCurveSizeInBytes),
          ec_point_xy->x.get());
      if (!res.ok()) {
        return util::Status(
            absl::StatusCode::kInternal,
            absl::StrCat(res.message(), " serializing the x coordinate"));
      }

      res = BignumToBinaryPadded(
          absl::MakeSpan(&encoded_point[kCurveSizeInBytes], kCurveSizeInBytes),
          ec_point_xy->y.get());
      if (!res.ok()) {
        return util::Status(
            absl::StatusCode::kInternal,
            absl::StrCat(res.message(), " serializing the y coordinate"));
      }
      return encoded_point;
    }
    default:
      return util::Status(absl::StatusCode::kInternal,
                          "Unsupported point format");
  }
}

util::StatusOr<SslUniquePtr<EC_POINT>> EcPointDecode(
    EllipticCurveType curve, EcPointFormat format, absl::string_view encoded) {
  switch (format) {
    case EcPointFormat::UNCOMPRESSED:
    case EcPointFormat::COMPRESSED:
      return SslGetEcPointFromEncoded(curve, format, encoded);
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      util::StatusOr<SslUniquePtr<EC_GROUP>> group =
          EcGroupFromCurveType(curve);
      if (!group.ok()) {
        return group.status();
      }
      const int kCurveSizeInBytes = SslEcFieldSizeInBytes(group->get());
      if (encoded.size() != 2 * kCurveSizeInBytes) {
        return util::Status(
            absl::StatusCode::kInternal,
            absl::StrCat("Encoded point's size is ", encoded.size(),
                         " bytes; expected ", 2 * kCurveSizeInBytes));
      }
      // SslGetEcPoint already checks if the point is on curve so we can return
      // directly.
      return SslGetEcPointFromCoordinates(group->get(),
                                          encoded.substr(0, kCurveSizeInBytes),
                                          encoded.substr(kCurveSizeInBytes));
    }
    default:
      return util::Status(absl::StatusCode::kInternal, "Unsupported format");
  }
}

util::StatusOr<SslUniquePtr<EC_GROUP>> EcGroupFromCurveType(
    EllipticCurveType curve_type) {
  EC_GROUP *ec_group = nullptr;
  switch (curve_type) {
    case EllipticCurveType::NIST_P256: {
      ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      break;
    }
    case EllipticCurveType::NIST_P384: {
      ec_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
      break;
    }
    case EllipticCurveType::NIST_P521: {
      ec_group = EC_GROUP_new_by_curve_name(NID_secp521r1);
      break;
    }
    default:
      return util::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
  if (ec_group == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EC_GROUP_new_by_curve_name failed");
  }
  return {SslUniquePtr<EC_GROUP>(ec_group)};
}

util::StatusOr<EllipticCurveType> CurveTypeFromEcGroup(const EC_GROUP *group) {
  if (group == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Null group provided");
  }
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

util::StatusOr<SslUniquePtr<EC_POINT>> GetEcPoint(EllipticCurveType curve,
                                                  absl::string_view pubx,
                                                  absl::string_view puby) {
  util::StatusOr<SslUniquePtr<EC_GROUP>> group = EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }
  return SslGetEcPointFromCoordinates(group->get(), pubx, puby);
}

util::StatusOr<util::SecretData> ComputeEcdhSharedSecret(
    EllipticCurveType curve, const BIGNUM *priv_key, const EC_POINT *pub_key) {
  util::StatusOr<internal::SslUniquePtr<EC_GROUP>> priv_group =
      internal::EcGroupFromCurveType(curve);
  if (!priv_group.ok()) {
    return priv_group.status();
  }
  if (EC_POINT_is_on_curve(priv_group->get(), pub_key, /*ctx=*/nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Public key is not on curve ",
                                     subtle::EnumToString(curve)));
  }

  // Compute the shared point and make sure it is on `curve`.
  internal::SslUniquePtr<EC_POINT> shared_point(
      EC_POINT_new(priv_group->get()));
  if (EC_POINT_mul(priv_group->get(), shared_point.get(), /*n=*/nullptr,
                   pub_key, priv_key, /*ctx=*/nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "Point multiplication failed");
  }
  if (EC_POINT_is_on_curve(priv_group->get(), shared_point.get(),
                           /*ctx=*/nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Shared point is not on curve ",
                                     subtle::EnumToString(curve)));
  }

  util::StatusOr<EcPointCoordinates> shared_point_coordinates =
      SslGetEcPointCoordinates(priv_group->get(), shared_point.get());
  if (!shared_point_coordinates.ok()) {
    return shared_point_coordinates.status();
  }

  // We need only the x coordinate.
  return internal::BignumToSecretData(shared_point_coordinates->x.get(),
                                      SslEcFieldSizeInBytes(priv_group->get()));
}

util::StatusOr<std::string> EcSignatureIeeeToDer(const EC_GROUP *group,
                                                 absl::string_view ieee_sig) {
  const size_t kFieldSizeInBytes = SslEcFieldSizeInBytes(group);
  if (ieee_sig.size() != kFieldSizeInBytes * 2) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Signature is not valid.");
  }
  util::StatusOr<SslUniquePtr<BIGNUM>> r =
      internal::StringToBignum(ieee_sig.substr(0, kFieldSizeInBytes));
  if (!r.ok()) {
    return r.status();
  }
  util::StatusOr<SslUniquePtr<BIGNUM>> s =
      internal::StringToBignum(ieee_sig.substr(kFieldSizeInBytes));
  if (!s.ok()) {
    return s.status();
  }
  internal::SslUniquePtr<ECDSA_SIG> ecdsa(ECDSA_SIG_new());
  if (ECDSA_SIG_set0(ecdsa.get(), r->get(), s->get()) != 1) {
    return util::Status(absl::StatusCode::kInternal, "ECDSA_SIG_set0 failed");
  }
  // ECDSA_SIG_set0 takes ownership of s and r's pointers.
  r->release();
  s->release();

  return SslEcdsaSignatureToBytes(ecdsa.get());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
