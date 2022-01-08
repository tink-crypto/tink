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
#include "tink/util/errors.h"
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

  // In FIPS only mode we check here if the modulus is 2048- or 3072-bit, as
  // these are the only size which is covered by the FIPS validation and
  // supported by Tink. See
  // https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3318
  if (IsFipsModeEnabled()) {
    if (modulus_size != 2048 && modulus_size != 3072) {
      return util::Status(
          absl::StatusCode::kInternal,
          absl::StrCat("Modulus size is ", modulus_size,
                       " only modulus size 2048 or 3072 is supported."));
    }
  }

  return util::OkStatus();
}

util::Status ValidateRsaPublicExponent(const BIGNUM *exponent) {
  if (exponent == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent must not be NULL.");
  }

  if (BN_is_odd(exponent) == 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent must be odd.");
  }

  if (CompareBignumWithWord(exponent, /*word=*/65536) <= 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Public exponent must be greater than 65536.");
  }

  // OpenSSL doesn't pose a limit to the size of the exponent, so for
  // consistency w.r.t. BoringSSL, we enforce it here.
  if (BN_num_bits(exponent) > 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Exponent size must be smaller than 32 bits");
  }
  return util::OkStatus();
}

util::Status ValidateRsaPublicExponent(absl::string_view exponent) {
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(exponent);
  if (!e.ok()) {
    return e.status();
  }
  return ValidateRsaPublicExponent(e->get());
}

util::Status NewRsaKeyPair(int modulus_size_in_bits, const BIGNUM *e,
                           RsaPrivateKey *private_key,
                           RsaPublicKey *public_key) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Could not initialize RSA.");
  }

  util::Status exponent_validation_res = ValidateRsaPublicExponent(e);
  if (!exponent_validation_res.ok()) {
    return exponent_validation_res;
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

util::Status GetRsaModAndExponents(const RsaPrivateKey &key, RSA *rsa) {
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(key.n);
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(key.e);
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> d =
      internal::StringToBignum(util::SecretDataAsStringView(key.d));
  if (!n.ok()) {
    return n.status();
  }
  if (!e.ok()) {
    return e.status();
  }
  if (!d.ok()) {
    return d.status();
  }
  if (RSA_set0_key(rsa, n->get(), e->get(), d->get()) != 1) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  // The RSA object takes ownership when RSA_set0_key is called.
  n->release();
  e->release();
  d->release();
  return util::OkStatus();
}

util::Status GetRsaPrimeFactors(const RsaPrivateKey &key, RSA *rsa) {
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> p =
      internal::StringToBignum(util::SecretDataAsStringView(key.p));
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> q =
      internal::StringToBignum(util::SecretDataAsStringView(key.q));
  if (!p.ok()) {
    return p.status();
  }
  if (!q.ok()) {
    return q.status();
  }
  if (RSA_set0_factors(rsa, p->get(), q->get()) != 1) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  p->release();
  q->release();
  return util::OkStatus();
}

util::Status GetRsaCrtParams(const RsaPrivateKey &key, RSA *rsa) {
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> dp =
      internal::StringToBignum(util::SecretDataAsStringView(key.dp));
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> dq =
      internal::StringToBignum(util::SecretDataAsStringView(key.dq));
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> crt =
      internal::StringToBignum(util::SecretDataAsStringView(key.crt));
  if (!dp.ok()) {
    return dp.status();
  }
  if (!dq.ok()) {
    return dq.status();
  }
  if (!crt.ok()) {
    return crt.status();
  }
  if (RSA_set0_crt_params(rsa, dp->get(), dq->get(), crt->get()) != 1) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
  dp->release();
  dq->release();
  crt->release();
  return util::OkStatus();
}

util::StatusOr<internal::SslUniquePtr<RSA>> RsaPrivateKeyToRsa(
    const RsaPrivateKey &private_key) {
  auto n = internal::StringToBignum(private_key.n);
  if (!n.ok()) {
    return n.status();
  }
  auto validation_result = ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!validation_result.ok()) {
    return validation_result;
  }
  // Check RSA's public exponent
  auto exponent_status = ValidateRsaPublicExponent(private_key.e);
  if (!exponent_status.ok()) {
    return exponent_status;
  }
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "BoringSsl RSA allocation error");
  }
  util::Status status = GetRsaModAndExponents(private_key, rsa.get());
  if (!status.ok()) {
    return status;
  }
  status = GetRsaPrimeFactors(private_key, rsa.get());
  if (!status.ok()) {
    return status;
  }
  status = GetRsaCrtParams(private_key, rsa.get());
  if (!status.ok()) {
    return status;
  }

  if (RSA_check_key(rsa.get()) == 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
#ifdef OPENSSL_IS_BORINGSSL
  if (RSA_check_fips(rsa.get()) == 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Could not load RSA key: ", internal::GetSslErrors()));
  }
#endif
  return rsa;
}

util::StatusOr<internal::SslUniquePtr<RSA>> RsaPublicKeyToRsa(
    const RsaPublicKey &public_key) {
  auto n = internal::StringToBignum(public_key.n);
  if (!n.ok()) {
    return n.status();
  }
  auto e = internal::StringToBignum(public_key.e);
  if (!e.ok()) {
    return e.status();
  }
  auto validation_result = ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!validation_result.ok()) {
    return validation_result;
  }
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal, "RSA allocation error");
  }
  // The value d is null for a public RSA key.
  if (RSA_set0_key(rsa.get(), n->get(), e->get(),
                   /*d=*/nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal, "Could not set RSA key.");
  }
  n->release();
  e->release();
  return rsa;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
