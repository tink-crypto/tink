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
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/errors.h"

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

}  // namespace

// static
util::StatusOr<std::string> SubtleUtilBoringSSL::bn2str(const BIGNUM *bn,
                                                   size_t len) {
  std::unique_ptr<uint8_t[]> res(new uint8_t[len]);
  if (1 != BN_bn2bin_padded(res.get(), len, bn)) {
    return util::Status(util::error::INTERNAL, "Value too large");
  }
  return std::string(reinterpret_cast<const char *>(res.get()), len);
}

// static
util::StatusOr<bssl::UniquePtr<BIGNUM>> SubtleUtilBoringSSL::str2bn(
    absl::string_view s) {
  bssl::UniquePtr<BIGNUM> bn(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(s.data()), s.length(),
                nullptr /* ret */));
  if (bn.get() == nullptr) {
    return util::Status(util::error::INTERNAL, "BIGNUM allocation failed");
  }
  return std::move(bn);
}

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
util::StatusOr<SubtleUtilBoringSSL::EcKey> SubtleUtilBoringSSL::GetNewEcKey(
    EllipticCurveType curve_type) {
  auto status_or_group(SubtleUtilBoringSSL::GetEcGroup(curve_type));
  if (!status_or_group.ok()) return status_or_group.status();
  bssl::UniquePtr<EC_GROUP> group(status_or_group.ValueOrDie());
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group.get());
  EC_KEY_generate_key(key.get());
  const BIGNUM *priv_key = EC_KEY_get0_private_key(key.get());
  const EC_POINT *pub_key = EC_KEY_get0_public_key(key.get());
  bssl::UniquePtr<BIGNUM> pub_key_x_bn(BN_new());
  bssl::UniquePtr<BIGNUM> pub_key_y_bn(BN_new());
  if (!EC_POINT_get_affine_coordinates_GFp(group.get(), pub_key,
                                           pub_key_x_bn.get(),
                                           pub_key_y_bn.get(), nullptr)) {
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
  if (1 !=
      EC_POINT_get_affine_coordinates_GFp(priv_group.get(), shared_point.get(),
                                          shared_x.get(), nullptr, nullptr)) {
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
      bssl::UniquePtr<BIGNUM> x(BN_new());
      bssl::UniquePtr<BIGNUM> y(BN_new());
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
    case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED: {
      bssl::UniquePtr<BIGNUM> x(BN_new());
      bssl::UniquePtr<BIGNUM> y(BN_new());
      if (nullptr == x.get() || nullptr == y.get()) {
        return util::Status(
            util::error::INTERNAL,
            "Openssl internal error allocating memory for coordinates");
      }
      std::unique_ptr<uint8_t[]> encoded(new uint8_t[2 * curve_size_in_bytes]);

      if (1 != EC_POINT_get_affine_coordinates_GFp(group.get(), point, x.get(),
                                                   y.get(), nullptr)) {
        return util::Status(util::error::INTERNAL,
                            "Openssl internal error getting coordinates");
      }
      if (1 != BN_bn2bin_padded(reinterpret_cast<uint8_t *>(encoded.get()),
                                curve_size_in_bytes, x.get())) {
        return util::Status(util::error::INTERNAL,
                            "Openssl internal error serializing x coordinate");
      }
      if (1 != BN_bn2bin_padded(reinterpret_cast<uint8_t *>(
                                    encoded.get() + curve_size_in_bytes),
                                curve_size_in_bytes, y.get())) {
        return util::Status(util::error::INTERNAL,
                            "Openssl internal error serializing y coordinate");
      }
      return std::string(reinterpret_cast<const char *>(encoded.get()),
                    2 * curve_size_in_bytes);
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
util::Status SubtleUtilBoringSSL::ValidateSignatureHash(HashType sig_hash) {
  switch (sig_hash) {
    case HashType::SHA256: /* fall through */
    case HashType::SHA512:
      return util::Status::OK;
    case HashType::SHA1:
      return util::Status(util::error::INVALID_ARGUMENT,
                          "SHA1 is not safe for digital signature");
    default:
      return util::Status(util::error::INVALID_ARGUMENT,
                          "Unsupported hash function");
  }
}

// static
util::Status SubtleUtilBoringSSL::ValidateRsaModulusSize(size_t modulus_size) {
  if (modulus_size < 2048) {
    return ToStatusF(
        util::error::INVALID_ARGUMENT,
        "Modulus size is %zu; only modulus size >= 2048-bit is supported",
        modulus_size);
  }
  return util::Status::OK;
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

// static
absl::string_view SubtleUtilBoringSSL::EnsureNonNull(absl::string_view str) {
  if (str.empty() && str.data() == nullptr) {
    return absl::string_view("");
  }
  return str;
}

util::Status SubtleUtilBoringSSL::GetNewRsaKeyPair(
    int modulus_size_in_bits, const BIGNUM *e,
    SubtleUtilBoringSSL::RsaPrivateKey *private_key,
    SubtleUtilBoringSSL::RsaPublicKey *public_key) {
  bssl::UniquePtr<RSA> rsa(RSA_new());
  if (rsa == nullptr) {
    return util::Status(util::error::INTERNAL, "Could not initialize RSA.");
  }

  bssl::UniquePtr<BIGNUM> e_copy(BN_new());
  if (BN_copy(e_copy.get(), e) == nullptr) {
    return util::Status(util::error::INTERNAL, GetErrors());
  }
  if (RSA_generate_key_ex(rsa.get(), modulus_size_in_bits, e_copy.get(),
                          /*cb=*/nullptr) != 1) {
    return util::Status(
        util::error::INTERNAL,
        absl::StrCat("Error generating private key: ", GetErrors()));
  }

  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);

  // Save exponents.
  auto n_str = bn2str(n_bn, BN_num_bytes(n_bn));
  auto e_str = bn2str(e_bn, BN_num_bytes(e_bn));
  auto d_str = bn2str(d_bn, BN_num_bytes(d_bn));
  if (!n_str.ok()) return n_str.status();
  if (!e_str.ok()) return e_str.status();
  if (!d_str.ok()) return d_str.status();
  private_key->n = std::move(n_str.ValueOrDie());
  private_key->e = std::move(e_str.ValueOrDie());
  private_key->d = std::move(d_str.ValueOrDie());

  public_key->n = private_key->n;
  public_key->e = private_key->e;

  // Save factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);
  auto p_str = bn2str(p_bn, BN_num_bytes(p_bn));
  auto q_str = bn2str(q_bn, BN_num_bytes(q_bn));
  if (!p_str.ok()) return p_str.status();
  if (!q_str.ok()) return q_str.status();
  private_key->p = std::move(p_str.ValueOrDie());
  private_key->q = std::move(q_str.ValueOrDie());

  // Save CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &crt_bn);
  auto dp_str = bn2str(dp_bn, BN_num_bytes(dp_bn));
  auto dq_str = bn2str(dq_bn, BN_num_bytes(dq_bn));
  auto crt_str = bn2str(crt_bn, BN_num_bytes(crt_bn));
  if (!dp_str.ok()) return dp_str.status();
  if (!dq_str.ok()) return dq_str.status();
  if (!crt_str.ok()) return crt_str.status();
  private_key->dp = std::move(dp_str.ValueOrDie());
  private_key->dq = std::move(dq_str.ValueOrDie());
  private_key->crt = std::move(crt_str.ValueOrDie());

  return util::OkStatus();
}

// static
util::Status SubtleUtilBoringSSL::CopyKey(
    const SubtleUtilBoringSSL::RsaPrivateKey &key, RSA *rsa) {
  auto n = SubtleUtilBoringSSL::str2bn(key.n);
  auto e = SubtleUtilBoringSSL::str2bn(key.e);
  auto d = SubtleUtilBoringSSL::str2bn(key.d);
  if (!n.ok()) return n.status();
  if (!e.ok()) return e.status();
  if (!d.ok()) return d.status();
  if (RSA_set0_key(rsa, n.ValueOrDie().get(), e.ValueOrDie().get(),
                   d.ValueOrDie().get()) != 1) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Could not load RSA key: ",
                                     SubtleUtilBoringSSL::GetErrors()));
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
  auto p = SubtleUtilBoringSSL::str2bn(key.p);
  auto q = SubtleUtilBoringSSL::str2bn(key.q);
  if (!p.ok()) return p.status();
  if (!q.ok()) return q.status();
  if (RSA_set0_factors(rsa, p.ValueOrDie().get(), q.ValueOrDie().get()) != 1) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Could not load RSA key: ",
                                     SubtleUtilBoringSSL::GetErrors()));
  }
  p.ValueOrDie().release();
  q.ValueOrDie().release();
  return util::OkStatus();
}

// static
util::Status SubtleUtilBoringSSL::CopyCrtParams(
    const SubtleUtilBoringSSL::RsaPrivateKey &key, RSA *rsa) {
  auto dp = SubtleUtilBoringSSL::str2bn(key.dp);
  auto dq = SubtleUtilBoringSSL::str2bn(key.dq);
  auto crt = SubtleUtilBoringSSL::str2bn(key.crt);
  if (!dp.ok()) return dp.status();
  if (!dq.ok()) return dq.status();
  if (!crt.ok()) return crt.status();
  if (RSA_set0_crt_params(rsa, dp.ValueOrDie().get(), dq.ValueOrDie().get(),
                          crt.ValueOrDie().get()) != 1) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Could not load RSA key: ",
                                     SubtleUtilBoringSSL::GetErrors()));
  }
  dp.ValueOrDie().release();
  dq.ValueOrDie().release();
  crt.ValueOrDie().release();
  return util::OkStatus();
}

namespace boringssl {

util::StatusOr<std::vector<uint8_t>> ComputeHash(absl::string_view input,
                                                 const EVP_MD &hasher) {
  input = SubtleUtilBoringSSL::EnsureNonNull(input);
  std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
  uint32_t digest_length = 0;
  if (EVP_Digest(input.data(), input.length(), digest.data(), &digest_length,
                 &hasher, /*impl=*/nullptr) != 1) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Openssl internal error computing hash: ",
                                     SubtleUtilBoringSSL::GetErrors()));
  }
  digest.resize(digest_length);
  return digest;
}

}  // namespace boringssl

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
