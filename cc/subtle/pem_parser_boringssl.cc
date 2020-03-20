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
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
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
util::Status VerifyRsaKey(const RSA *rsa_key) {
  if (rsa_key == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Invalid RSA key format");
  }
  // Check the key parameters.
  if (RSA_check_key(rsa_key) != kBsslOk) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Invalid RSA key format");
  }
  return util::OkStatus();
}

}  // namespace

// static.
util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::RsaPublicKey>>
PemParser::ParseRsaPublicKey(absl::string_view pem_serialized_key) {
  // Read the RSA key into EVP_PKEY.
  bssl::UniquePtr<BIO> rsa_key_bio(BIO_new(BIO_s_mem()));
  BIO_write(rsa_key_bio.get(), pem_serialized_key.data(),
            pem_serialized_key.size());

  bssl::UniquePtr<EVP_PKEY> evp_rsa_key(PEM_read_bio_PUBKEY(
      rsa_key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));

  if (evp_rsa_key == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "PEM Public Key parsing failed");
  }
  // No need to free bssl_rsa_key after use.
  RSA *bssl_rsa_key = EVP_PKEY_get0_RSA(evp_rsa_key.get());
  auto is_valid = VerifyRsaKey(bssl_rsa_key);
  if (!is_valid.ok()) {
    return is_valid;
  }

  // Get the public key paramters.
  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(bssl_rsa_key, &n_bn, &e_bn, &d_bn);

  // Public key should not have d_bn set.
  if (d_bn != nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Invalid RSA Public Key format");
  }

  // We are only interested in e and n.
  auto n_str_statusor = SubtleUtilBoringSSL::bn2str(n_bn, BN_num_bytes(n_bn));
  auto e_str_statusor = SubtleUtilBoringSSL::bn2str(e_bn, BN_num_bytes(e_bn));
  if (!n_str_statusor.ok()) return n_str_statusor.status();
  if (!e_str_statusor.ok()) return e_str_statusor.status();
  auto rsa_public_key = absl::make_unique<SubtleUtilBoringSSL::RsaPublicKey>();
  rsa_public_key->e = std::move(e_str_statusor.ValueOrDie());
  rsa_public_key->n = std::move(n_str_statusor.ValueOrDie());

  return rsa_public_key;
}

// static.
util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::RsaPrivateKey>>
PemParser::ParseRsaPrivateKey(absl::string_view pem_serialized_key) {
  // Read the private key into EVP_PKEY.
  bssl::UniquePtr<BIO> rsa_key_bio(BIO_new(BIO_s_mem()));
  BIO_write(rsa_key_bio.get(), pem_serialized_key.data(),
            pem_serialized_key.size());

  // BoringSSL APIs to parse the PEM data.
  bssl::UniquePtr<EVP_PKEY> evp_rsa_key(PEM_read_bio_PrivateKey(
      rsa_key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));

  if (evp_rsa_key == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "PEM Private Key parsing failed");
  }

  // No need to free bssl_rsa_key after use.
  RSA *bssl_rsa_key = EVP_PKEY_get0_RSA(evp_rsa_key.get());

  auto is_valid_key = VerifyRsaKey(bssl_rsa_key);
  if (!is_valid_key.ok()) {
    return is_valid_key;
  }

  const BIGNUM *n_bn, *e_bn, *d_bn;
  RSA_get0_key(bssl_rsa_key, &n_bn, &e_bn, &d_bn);

  // Save exponents.
  auto rsa_private_key =
      absl::make_unique<SubtleUtilBoringSSL::RsaPrivateKey>();
  auto n_str = SubtleUtilBoringSSL::bn2str(n_bn, BN_num_bytes(n_bn));
  auto e_str = SubtleUtilBoringSSL::bn2str(e_bn, BN_num_bytes(e_bn));
  auto d_str = SubtleUtilBoringSSL::bn2str(d_bn, BN_num_bytes(d_bn));
  if (!n_str.ok()) return n_str.status();
  if (!e_str.ok()) return e_str.status();
  if (!d_str.ok()) return d_str.status();
  rsa_private_key->n = std::move(n_str.ValueOrDie());
  rsa_private_key->e = std::move(e_str.ValueOrDie());
  rsa_private_key->d = std::move(d_str.ValueOrDie());

  // Save factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(bssl_rsa_key, &p_bn, &q_bn);
  auto p_str = SubtleUtilBoringSSL::bn2str(p_bn, BN_num_bytes(p_bn));
  auto q_str = SubtleUtilBoringSSL::bn2str(q_bn, BN_num_bytes(q_bn));
  if (!p_str.ok()) return p_str.status();
  if (!q_str.ok()) return q_str.status();
  rsa_private_key->p = std::move(p_str.ValueOrDie());
  rsa_private_key->q = std::move(q_str.ValueOrDie());

  // Save CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(bssl_rsa_key, &dp_bn, &dq_bn, &crt_bn);
  auto dp_str = SubtleUtilBoringSSL::bn2str(dp_bn, BN_num_bytes(dp_bn));
  auto dq_str = SubtleUtilBoringSSL::bn2str(dq_bn, BN_num_bytes(dq_bn));
  auto crt_str = SubtleUtilBoringSSL::bn2str(crt_bn, BN_num_bytes(crt_bn));
  if (!dp_str.ok()) return dp_str.status();
  if (!dq_str.ok()) return dq_str.status();
  if (!crt_str.ok()) return crt_str.status();
  rsa_private_key->dp = std::move(dp_str.ValueOrDie());
  rsa_private_key->dq = std::move(dq_str.ValueOrDie());
  rsa_private_key->crt = std::move(crt_str.ValueOrDie());

  return rsa_private_key;
}

util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>>
PemParser::ParseEcPublicKey(absl::string_view pem_serialized_key) {
  return util::Status(util::error::UNIMPLEMENTED,
                      "PEM EC Public Key parsing is unimplemented");
}

util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>>
PemParser::ParseEcPrivateKey(absl::string_view pem_serialized_key) {
  return util::Status(util::error::UNIMPLEMENTED,
                      "PEM EC Private Key parsing is unimplemented");
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
