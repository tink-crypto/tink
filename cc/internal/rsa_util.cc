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
#include "tink/internal/rsa_util.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status ValidateRsaModulusSize(size_t modulus_size) {
  if (modulus_size < 2048) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Modulus size is ", modulus_size,
                     " only modulus size >= 2048-bit is supported"));
  }

  // In FIPS only mode we check here if the modulus is 3072, as this is the
  // only size which is covered by the FIPS validation and supported by Tink.
  // See
  // https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3318
  if (IsFipsModeEnabled() && (modulus_size != 3072)) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Modulus size is ", modulus_size,
                                     " only modulus size 3072 is supported "));
  }

  return util::OkStatus();
}

util::Status ValidateRsaPublicExponent(absl::string_view exponent) {
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(exponent);
  if (!e.ok()) {
    return e.status();
  }
  if (!BN_is_odd(e->get())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent must be odd.");
  }

  if (BN_cmp_word(e->get(), 65536) <= 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent must be greater than 65536.");
  }

  return util::OkStatus();
}

util::Status NewRsaKeyPair(int modulus_size_in_bits, const BIGNUM *e,
                           RsaPrivateKey *private_key,
                           RsaPublicKey *public_key) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Could not initialize RSA.");
  }

  internal::SslUniquePtr<BIGNUM> e_copy(BN_new());
  if (BN_copy(e_copy.get(), e) == nullptr) {
    return util::Status(absl::StatusCode::kInternal, internal::GetSslErrors());
  }
  if (RSA_generate_key_ex(rsa.get(), modulus_size_in_bits, e_copy.get(),
                          /*cb=*/nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
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
  private_key->n = *std::move(n_str);
  private_key->e = *std::move(e_str);
  private_key->d = *std::move(d_str);
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
  private_key->p = *std::move(p_str);
  private_key->q = *std::move(q_str);

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
  private_key->dp = *std::move(dp_str);
  private_key->dq = *std::move(dq_str);
  private_key->crt = *std::move(crt_str);

  return util::OkStatus();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
