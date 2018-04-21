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
#include "tink/subtle/common_enums.h"
#include "openssl/ec.h"
#include "openssl/err.h"


namespace crypto {
namespace tink {
namespace subtle {

namespace {

util::StatusOr<std::string> bn2str(const BIGNUM* bn, size_t len) {
  std::unique_ptr<uint8_t[]> res(new uint8_t[len]);
  if (1 != BN_bn2bin_padded(res.get(), len, bn)) {
    return util::Status(util::error::INTERNAL, "Value too large");
  }
  return std::string(reinterpret_cast<const char*>(res.get()), len);
}

size_t ScalarSizeInBytes(const EC_GROUP* group) {
  return BN_num_bytes(EC_GROUP_get0_order(group));
}

size_t FieldElementSizeInBytes(const EC_GROUP* group) {
  unsigned degree_bits = EC_GROUP_get_degree(group);
  return (degree_bits + 7) / 8;
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
      return util::Status(util::error::UNIMPLEMENTED,
                          "Unsupported elliptic curve");
  }
}

// static
util::StatusOr<EC_POINT *> SubtleUtilBoringSSL::GetEcPoint(
    EllipticCurveType curve, absl::string_view pubx, absl::string_view puby) {
  bssl::UniquePtr<BIGNUM> bn_x(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(pubx.data()),
                pubx.size(), nullptr));
  bssl::UniquePtr<BIGNUM> bn_y(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(puby.data()),
                puby.length(), nullptr));
  if (bn_x.get() == nullptr || bn_y.get() == nullptr) {
    return util::Status(util::error::INTERNAL, "BN_bin2bn failed");
  }
  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  bssl::UniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
  bssl::UniquePtr<EC_POINT> pub_key(EC_POINT_new(group.get()));
  if (1 != EC_POINT_set_affine_coordinates_GFp(
               group.get(), pub_key.get(), bn_x.get(), bn_y.get(), nullptr)) {
    return util::Status(util::error::INTERNAL,
                        "EC_POINT_set_affine_coordinates_GFp failed");
  }
  return pub_key.release();
}

// static
util::StatusOr<SubtleUtilBoringSSL::EcKey>
SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType curve_type) {
  auto status_or_group(SubtleUtilBoringSSL::GetEcGroup(curve_type));
  if (!status_or_group.ok()) return status_or_group.status();
  bssl::UniquePtr<EC_GROUP> group(status_or_group.ValueOrDie());
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group.get());
  EC_KEY_generate_key(key.get());
  const BIGNUM* priv_key = EC_KEY_get0_private_key(key.get());
  const EC_POINT* pub_key = EC_KEY_get0_public_key(key.get());
  bssl::UniquePtr<BIGNUM> pub_key_x_bn(BN_new());
  bssl::UniquePtr<BIGNUM> pub_key_y_bn(BN_new());
  if (!EC_POINT_get_affine_coordinates_GFp(group.get(), pub_key,
          pub_key_x_bn.get(), pub_key_y_bn.get(), nullptr)) {
    return util::Status(util::error::INTERNAL,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }
  EcKey ec_key;
  ec_key.curve = curve_type;
  auto pub_x_str =
      bn2str(pub_key_x_bn.get(), FieldElementSizeInBytes(group.get()));
  if (!pub_x_str.ok()) {
    return pub_x_str.status();
  }
  ec_key.pub_x = pub_x_str.ValueOrDie();
  auto pub_y_str =
      bn2str(pub_key_y_bn.get(), FieldElementSizeInBytes(group.get()));
  if (!pub_y_str.ok()) {
    return pub_y_str.status();
  }
  ec_key.pub_y = pub_y_str.ValueOrDie();
  auto priv_key_str = bn2str(priv_key, ScalarSizeInBytes(group.get()));
  if (!priv_key_str.ok()) {
    return priv_key_str.status();
  }
  ec_key.priv = priv_key_str.ValueOrDie();
  return ec_key;
}

// static
util::StatusOr<const EVP_MD *> SubtleUtilBoringSSL::EvpHash(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return EVP_sha1();
    case HashType::SHA256:
      return EVP_sha256();
    case HashType::SHA512:
      return EVP_sha512();
    default:
      return util::Status(util::error::UNIMPLEMENTED, "Unsupported hash");
  }
}

// static
util::StatusOr<std::string> SubtleUtilBoringSSL::ComputeEcdhSharedSecret(
    EllipticCurveType curve, const BIGNUM *priv_key, const EC_POINT *pub_key) {
  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  bssl::UniquePtr<EC_GROUP> priv_group(status_or_ec_group.ValueOrDie());
  bssl::UniquePtr<EC_POINT> shared_point(EC_POINT_new(priv_group.get()));
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
  bssl::UniquePtr<BIGNUM> shared_x(BN_new());
  if (1 != EC_POINT_get_affine_coordinates_GFp(priv_group.get(),
               shared_point.get(), shared_x.get(), nullptr, nullptr)) {
    return util::Status(util::error::INTERNAL,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }
  return bn2str(shared_x.get(), FieldElementSizeInBytes(priv_group.get()));
}

// static
util::StatusOr<EC_POINT *> SubtleUtilBoringSSL::EcPointDecode(
    EllipticCurveType curve, EcPointFormat format, absl::string_view encoded) {
  auto status_or_ec_group = GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  bssl::UniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
  switch (format) {
    case EcPointFormat::UNCOMPRESSED:
      if (static_cast<int>(encoded[0]) != 0x04) {
        return util::Status(
            util::error::INTERNAL,
            "Uncompressed point should start with 0x04, but input doesn't");
      }
      if (1 !=
          EC_POINT_oct2point(group.get(), point.get(),
                             reinterpret_cast<const uint8_t *>(encoded.data()),
                             encoded.size(), nullptr)) {
        return util::Status(util::error::INTERNAL, "EC_POINT_toc2point failed");
      }
      break;
    case EcPointFormat::COMPRESSED:
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
    default:
      return util::Status(util::error::INTERNAL, "Unsupported format");
  }
  if (1 != EC_POINT_is_on_curve(group.get(), point.get(), nullptr)) {
    return util::Status(util::error::INTERNAL, "Point is not on curve");
  }
  return point.release();
}

// static
util::StatusOr<std::string> SubtleUtilBoringSSL::EcPointEncode(
    EllipticCurveType curve, EcPointFormat format, const EC_POINT *point) {
  auto status_or_ec_group = GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  bssl::UniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
  unsigned curve_size_in_bytes = (EC_GROUP_get_degree(group.get()) + 7) / 8;
  if (1 != EC_POINT_is_on_curve(group.get(), point, nullptr)) {
    return util::Status(util::error::INTERNAL, "Point is not on curve");
  }
  switch (format) {
    case EcPointFormat::UNCOMPRESSED: {
      std::unique_ptr<uint8_t[]> encoded(
          new uint8_t[1 + 2 * curve_size_in_bytes]);
      size_t size = EC_POINT_point2oct(
          group.get(), point, POINT_CONVERSION_UNCOMPRESSED, encoded.get(),
          1 + 2 * curve_size_in_bytes, nullptr);
      if (size != 1 + 2 * curve_size_in_bytes) {
        return util::Status(util::error::INTERNAL, "EC_POINT_point2oct failed");
      }
      return std::string(reinterpret_cast<const char *>(encoded.get()),
                         1 + 2 * curve_size_in_bytes);
    }
    case EcPointFormat::COMPRESSED: {
      std::unique_ptr<uint8_t[]> encoded(new uint8_t[1 + curve_size_in_bytes]);
      size_t size = EC_POINT_point2oct(
          group.get(), point, POINT_CONVERSION_COMPRESSED, encoded.get(),
          1 + 2 * curve_size_in_bytes, nullptr);
      if (size != 1 + curve_size_in_bytes) {
        return util::Status(util::error::INTERNAL, "EC_POINT_point2oct failed");
      }
      return std::string(reinterpret_cast<const char *>(encoded.get()),
                         1 + curve_size_in_bytes);
    }
    default:
      return util::Status(util::error::INTERNAL, "Unsupported point format");
  }
}


// static
std::string SubtleUtilBoringSSL::GetErrors() {
  std::string ret;
  ERR_print_errors_cb(
      [](const char *str, size_t len, void *ctx) -> int {
        static_cast<std::string *>(ctx)->append(str, len);
        return 1;
      },
      &ret);
  return ret;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
