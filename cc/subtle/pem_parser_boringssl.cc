// Copyright 2018 Google Inc.
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
#include "tink/subtle/pem_parser_boringssl.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ec_key.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {
constexpr int kBsslOk = 1;

// Verifies that the given RSA pointer `rsa_key` points to a valid RSA key.
util::Status VerifyRsaKey(const RSA* rsa_key) {
  if (rsa_key == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid RSA key format");
  }
  // Check the key parameters.
  if (RSA_check_key(rsa_key) != kBsslOk) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid RSA key format");
  }
  return util::OkStatus();
}

// Verifies that the given ECDSA pointer `ecdsa_key` points to a valid ECDSA
// key.
util::Status VerifyEcdsaKey(const EC_KEY* ecdsa_key) {
  if (ecdsa_key == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ECDSA key format");
  }
  // Check the key parameters.
  if (EC_KEY_check_key(ecdsa_key) != kBsslOk) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ECDSA key format");
  }
  return util::OkStatus();
}

// Converts the public portion of a given SubtleUtilBoringSSL::EcKey,
// `subtle_ec_key`, into an OpenSSL EC key, `openssl_ec_key`.
util::Status ConvertSubtleEcKeyToOpenSslEcPublicKey(
    const SubtleUtilBoringSSL::EcKey& subtle_ec_key, EC_KEY* openssl_ec_key) {
  if (openssl_ec_key == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "`openssl_ec_key` arg cannot be NULL");
  }

  // Set the key's group (EC curve).
  auto group_statusor = SubtleUtilBoringSSL::GetEcGroup(subtle_ec_key.curve);
  if (!group_statusor.ok()) {
    return group_statusor.status();
  }
  internal::SslUniquePtr<EC_GROUP> group(group_statusor.ValueOrDie());
  if (group.get() == nullptr) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("failed to set EC group to curve ", subtle_ec_key.curve));
  }
  if (!EC_KEY_set_group(openssl_ec_key, group.get())) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("failed to set key group from EC group for curve ",
                     subtle_ec_key.curve));
  }

  // Create an EC point and initialize it from the key proto.
  internal::SslUniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
  if (!point.get()) {
    return util::Status(absl::StatusCode::kInternal,
                        "failed to allocate EC_POINT");
  }
  internal::SslUniquePtr<BIGNUM> x(BN_bin2bn(
      reinterpret_cast<const unsigned char*>(subtle_ec_key.pub_x.data()),
      subtle_ec_key.pub_x.length(), nullptr));
  internal::SslUniquePtr<BIGNUM> y(BN_bin2bn(
      reinterpret_cast<const unsigned char*>(subtle_ec_key.pub_y.data()),
      subtle_ec_key.pub_y.length(), nullptr));
  if (!EC_POINT_set_affine_coordinates_GFp(group.get(), point.get(), x.get(),
                                           y.get(), nullptr)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to set affine coordinates");
  }
  if (!EC_POINT_is_on_curve(group.get(), point.get(), nullptr)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to confirm EC point is on curve");
  }

  // Set the key's point from the EC point, created above.
  if (!EC_KEY_set_public_key(openssl_ec_key, point.get())) {
    return util::Status(absl::StatusCode::kInternal,
                        "failed to set public key");
  }

  return util::OkStatus();
}

// Converts a given SubtleUtilBoringSSL::EcKey, `subtle_ec_key`, into an OpenSSL
// EC key, `openssl_ec_key`.
util::Status ConvertSubtleEcKeyToOpenSslEcPrivateKey(
    const SubtleUtilBoringSSL::EcKey& subtle_ec_key, EC_KEY* openssl_ec_key) {
  if (openssl_ec_key == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "`openssl_ec_key` arg cannot be NULL");
  }
  util::Status status =
      ConvertSubtleEcKeyToOpenSslEcPublicKey(subtle_ec_key, openssl_ec_key);
  if (!status.ok()) {
    return status;
  }
  internal::SslUniquePtr<BIGNUM> x(BN_bin2bn(
      reinterpret_cast<const unsigned char*>(subtle_ec_key.priv.data()),
      subtle_ec_key.priv.size(), nullptr));
  if (!EC_KEY_set_private_key(openssl_ec_key, x.get())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to set private key");
  }
  if (!EC_KEY_check_key(openssl_ec_key)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed private key check");
  }
  return util::OkStatus();
}

// Converts an OpenSSL BIO (i.e., basic IO stream), `bio`, into a string.
util::StatusOr<std::string> ConvertBioToString(BIO* bio) {
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  std::string pem_material;
  if (mem->data && mem->length) {
    pem_material.assign(mem->data, mem->length);
  }
  if (pem_material.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to retrieve key material from BIO");
  }
  return pem_material;
}

}  // namespace

// static.
util::StatusOr<std::unique_ptr<internal::RsaPublicKey>>
PemParser::ParseRsaPublicKey(absl::string_view pem_serialized_key) {
  // Read the RSA key into EVP_PKEY.
  internal::SslUniquePtr<BIO> rsa_key_bio(BIO_new(BIO_s_mem()));
  BIO_write(rsa_key_bio.get(), pem_serialized_key.data(),
            pem_serialized_key.size());

  internal::SslUniquePtr<EVP_PKEY> evp_rsa_key(PEM_read_bio_PUBKEY(
      rsa_key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));

  if (evp_rsa_key == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Public Key parsing failed");
  }
  // No need to free bssl_rsa_key after use.
  RSA* bssl_rsa_key = EVP_PKEY_get0_RSA(evp_rsa_key.get());
  auto is_valid = VerifyRsaKey(bssl_rsa_key);
  if (!is_valid.ok()) {
    return is_valid;
  }

  // Get the public key parameters.
  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(bssl_rsa_key, &n_bn, &e_bn, &d_bn);

  // Public key should not have d_bn set.
  if (d_bn != nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid RSA Public Key format");
  }

  // We are only interested in e and n.
  auto n_str = internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  auto e_str = internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  if (!n_str.ok()) {
    return n_str.status();
  }
  if (!e_str.ok()) {
    return e_str.status();
  }
  auto rsa_public_key = absl::make_unique<internal::RsaPublicKey>();
  rsa_public_key->e = *std::move(e_str);
  rsa_public_key->n = *std::move(n_str);

  return rsa_public_key;
}

// static.
util::StatusOr<std::unique_ptr<internal::RsaPrivateKey>>
PemParser::ParseRsaPrivateKey(absl::string_view pem_serialized_key) {
  // Read the private key into EVP_PKEY.
  internal::SslUniquePtr<BIO> rsa_key_bio(BIO_new(BIO_s_mem()));
  BIO_write(rsa_key_bio.get(), pem_serialized_key.data(),
            pem_serialized_key.size());

  // BoringSSL APIs to parse the PEM data.
  internal::SslUniquePtr<EVP_PKEY> evp_rsa_key(PEM_read_bio_PrivateKey(
      rsa_key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));

  if (evp_rsa_key == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Private Key parsing failed");
  }

  // No need to free bssl_rsa_key after use.
  RSA* bssl_rsa_key = EVP_PKEY_get0_RSA(evp_rsa_key.get());

  auto is_valid_key = VerifyRsaKey(bssl_rsa_key);
  if (!is_valid_key.ok()) {
    return is_valid_key;
  }

  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(bssl_rsa_key, &n_bn, &e_bn, &d_bn);

  // Save exponents.
  auto rsa_private_key = absl::make_unique<internal::RsaPrivateKey>();
  auto n_str = internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  auto e_str = internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  auto d_str = internal::BignumToSecretData(d_bn, BN_num_bytes(d_bn));
  if (!n_str.ok()) {
    return n_str.status();
  }
  if (!e_str.ok()) {
    return e_str.status();
  }
  if (!d_str.ok()) {
    return d_str.status();
  }
  rsa_private_key->n = *std::move(n_str);
  rsa_private_key->e = *std::move(e_str);
  rsa_private_key->d = *std::move(d_str);

  // Save factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(bssl_rsa_key, &p_bn, &q_bn);
  auto p_str = internal::BignumToSecretData(p_bn, BN_num_bytes(p_bn));
  auto q_str = internal::BignumToSecretData(q_bn, BN_num_bytes(q_bn));
  if (!p_str.ok()) {
    return p_str.status();
  }
  if (!q_str.ok()) {
    return q_str.status();
  }
  rsa_private_key->p = *std::move(p_str);
  rsa_private_key->q = *std::move(q_str);

  // Save CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(bssl_rsa_key, &dp_bn, &dq_bn, &crt_bn);
  auto dp_str = internal::BignumToSecretData(dp_bn, BN_num_bytes(dp_bn));
  auto dq_str = internal::BignumToSecretData(dq_bn, BN_num_bytes(dq_bn));
  auto crt_str = internal::BignumToSecretData(crt_bn, BN_num_bytes(crt_bn));
  if (!dp_str.ok()) {
    return dp_str.status();
  }
  if (!dq_str.ok()) {
    return dq_str.status();
  }
  if (!crt_str.ok()) {
    return crt_str.status();
  }
  rsa_private_key->dp = *std::move(dp_str);
  rsa_private_key->dq = *std::move(dq_str);
  rsa_private_key->crt = *std::move(crt_str);

  return rsa_private_key;
}

util::StatusOr<std::string> PemParser::WriteRsaPublicKey(
    const internal::RsaPublicKey& rsa_public_key) {
  auto rsa_statusor = internal::RsaPublicKeyToRsa(rsa_public_key);
  if (!rsa_statusor.ok()) {
    return rsa_statusor.status();
  }

  internal::SslUniquePtr<RSA> rsa = std::move(rsa_statusor).ValueOrDie();
  internal::SslUniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_RSA_PUBKEY(bio.get(), rsa.get())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to write openssl RSA key to write bio");
  }
  return ConvertBioToString(bio.get());
}

util::StatusOr<std::string> PemParser::WriteRsaPrivateKey(
    const internal::RsaPrivateKey& rsa_private_key) {
  auto rsa_statusor = internal::RsaPrivateKeyToRsa(rsa_private_key);
  if (!rsa_statusor.ok()) {
    return rsa_statusor.status();
  }

  internal::SslUniquePtr<RSA> rsa = std::move(rsa_statusor).ValueOrDie();
  internal::SslUniquePtr<EVP_PKEY> evp(EVP_PKEY_new());
  EVP_PKEY_set1_RSA(evp.get(), rsa.get());

  internal::SslUniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_PrivateKey(bio.get(), evp.get(),
                                /*enc=*/nullptr, /*kstr=*/nullptr,
                                /*klen=*/0,
                                /*cb=*/nullptr, /*u=*/nullptr)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to write openssl RSA key to write bio");
  }
  return ConvertBioToString(bio.get());
}

util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>>
PemParser::ParseEcPublicKey(absl::string_view pem_serialized_key) {
  // Read the ECDSA key into EVP_PKEY.
  internal::SslUniquePtr<BIO> ecdsa_key_bio(BIO_new(BIO_s_mem()));
  BIO_write(ecdsa_key_bio.get(), pem_serialized_key.data(),
            pem_serialized_key.size());

  internal::SslUniquePtr<EVP_PKEY> evp_ecdsa_key(PEM_read_bio_PUBKEY(
      ecdsa_key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));

  if (evp_ecdsa_key == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Public Key parsing failed");
  }
  // No need to free bssl_ecdsa_key after use.
  EC_KEY* bssl_ecdsa_key = EVP_PKEY_get0_EC_KEY(evp_ecdsa_key.get());
  auto is_valid = VerifyEcdsaKey(bssl_ecdsa_key);
  if (!is_valid.ok()) {
    return is_valid;
  }

  // Get the public key parameters.
  internal::SslUniquePtr<BIGNUM> x_coordinate(BN_new());
  internal::SslUniquePtr<BIGNUM> y_coordinate(BN_new());
  const EC_POINT* public_point = EC_KEY_get0_public_key(bssl_ecdsa_key);
  const EC_GROUP* ec_group = EC_KEY_get0_group(bssl_ecdsa_key);
  EC_POINT_get_affine_coordinates(ec_group, public_point, x_coordinate.get(),
                                  y_coordinate.get(), nullptr);

  // Convert public key parameters and construct Subtle ECKey
  auto x_string = internal::BignumToString(x_coordinate.get(),
                                           BN_num_bytes(x_coordinate.get()));
  auto y_string = internal::BignumToString(y_coordinate.get(),
                                           BN_num_bytes(y_coordinate.get()));
  auto curve = SubtleUtilBoringSSL::GetCurve(ec_group);

  if (!x_string.ok()) return x_string.status();
  if (!y_string.ok()) return y_string.status();
  if (!curve.ok()) return curve.status();

  auto ecdsa_public_key = absl::make_unique<SubtleUtilBoringSSL::EcKey>();
  ecdsa_public_key->pub_x = std::move(x_string).ValueOrDie();
  ecdsa_public_key->pub_y = std::move(y_string).ValueOrDie();
  ecdsa_public_key->curve = std::move(curve).ValueOrDie();

  return ecdsa_public_key;
}

util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>>
PemParser::ParseEcPrivateKey(absl::string_view pem_serialized_key) {
  return util::Status(absl::StatusCode::kUnimplemented,
                      "PEM EC Private Key parsing is unimplemented");
}

util::StatusOr<std::string> PemParser::WriteEcPublicKey(
    const SubtleUtilBoringSSL::EcKey& ec_key) {
  internal::SslUniquePtr<EC_KEY> openssl_ec_key(EC_KEY_new());
  util::Status status =
      ConvertSubtleEcKeyToOpenSslEcPublicKey(ec_key, openssl_ec_key.get());
  if (!status.ok()) {
    return status;
  }
  internal::SslUniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_EC_PUBKEY(bio.get(), openssl_ec_key.get())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to write openssl EC key to write bio");
  }
  return ConvertBioToString(bio.get());
}

util::StatusOr<std::string> PemParser::WriteEcPrivateKey(
    const SubtleUtilBoringSSL::EcKey& ec_key) {
  internal::SslUniquePtr<EC_KEY> openssl_ec_key(EC_KEY_new());
  util::Status status =
      ConvertSubtleEcKeyToOpenSslEcPrivateKey(ec_key, openssl_ec_key.get());
  if (!status.ok()) {
    return status;
  }
  internal::SslUniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_ECPrivateKey(bio.get(), openssl_ec_key.get(),
                                  /*enc=*/nullptr, /*kstr=*/nullptr, /*klen=*/0,
                                  /*cb=*/nullptr, /*u=*/nullptr)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "failed to write openssl EC key to write bio");
  }
  return ConvertBioToString(bio.get());
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
