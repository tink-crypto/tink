// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/rsa_ssa_pss_private_key.h"

#include "absl/status/status.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::Status ValidateKeyPair(
    const BigInteger& public_exponent, const BigInteger& modulus,
    const RestrictedBigInteger& p, const RestrictedBigInteger& q,
    const RestrictedBigInteger& d, const RestrictedBigInteger& dp,
    const RestrictedBigInteger& dq, const RestrictedBigInteger& q_inv) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Internal RSA allocation error");
  }

  util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(modulus.GetValue());
  if (!n.ok()) {
    return n.status();
  }

  util::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(public_exponent.GetValue());
  if (!e.ok()) {
    return e.status();
  }

  util::StatusOr<internal::SslUniquePtr<BIGNUM>> d_bn =
      internal::StringToBignum(d.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!d_bn.ok()) {
    return d_bn.status();
  }

  util::StatusOr<internal::SslUniquePtr<BIGNUM>> p_bn =
      internal::StringToBignum(p.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!p_bn.ok()) {
    return p_bn.status();
  }
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> q_bn =
      internal::StringToBignum(q.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!q_bn.ok()) {
    return q_bn.status();
  }

  util::StatusOr<internal::SslUniquePtr<BIGNUM>> dp_bn =
      internal::StringToBignum(dp.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!dp_bn.ok()) {
    return dp_bn.status();
  }
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> dq_bn =
      internal::StringToBignum(dq.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!dq_bn.ok()) {
    return dq_bn.status();
  }
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> q_inv_bn =
      internal::StringToBignum(q_inv.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!q_inv_bn.ok()) {
    return q_inv_bn.status();
  }

  // Build RSA key from the given values.  The RSA object takes ownership of the
  // given values after the call.
  if (RSA_set0_key(rsa.get(), n->release(), e->release(), d_bn->release()) !=
          1 ||
      RSA_set0_factors(rsa.get(), p_bn->release(), q_bn->release()) != 1 ||
      RSA_set0_crt_params(rsa.get(), dp_bn->release(), dq_bn->release(),
                          q_inv_bn->release()) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "Internal RSA key loading error");
  }

  // Validate key.
  int check_key_status = RSA_check_key(rsa.get());
  if (check_key_status == 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "RSA key pair is not valid");
  }

  if (check_key_status == -1) {
    return util::Status(absl::StatusCode::kInternal,
                        "An error ocurred while checking the key");
  }

#ifdef OPENSSL_IS_BORINGSSL
  if (RSA_check_fips(rsa.get()) == 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "RSA key pair is not valid in FIPS mode");
  }
#endif

  return util::OkStatus();
}

}  // namespace

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPublicKey(
    const RsaSsaPssPublicKey& public_key) {
  public_key_ = public_key;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeP(
    const RestrictedBigInteger& p) {
  p_ = p;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeQ(
    const RestrictedBigInteger& q) {
  q_ = q;
  return *this;
}

RsaSsaPssPrivateKey::Builder&
RsaSsaPssPrivateKey::Builder::SetPrimeExponentP(
    const RestrictedBigInteger& dp) {
  dp_ = dp;
  return *this;
}

RsaSsaPssPrivateKey::Builder&
RsaSsaPssPrivateKey::Builder::SetPrimeExponentQ(
    const RestrictedBigInteger& dq) {
  dq_ = dq;
  return *this;
}

RsaSsaPssPrivateKey::Builder&
RsaSsaPssPrivateKey::Builder::SetPrivateExponent(
    const RestrictedBigInteger& d) {
  d_ = d;
  return *this;
}

RsaSsaPssPrivateKey::Builder&
RsaSsaPssPrivateKey::Builder::SetCrtCoefficient(
    const RestrictedBigInteger& q_inv) {
  q_inv_ = q_inv;
  return *this;
}

util::StatusOr<RsaSsaPssPrivateKey> RsaSsaPssPrivateKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!public_key_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the public key");
  }

  if (!p_.has_value() || !q_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting both prime factors");
  }

  if (!dp_.has_value() || !dq_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting both prime exponents");
  }

  if (!d_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the private exponent");
  }

  if (!q_inv_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the CRT coefficient");
  }

  // Validate key pair.
  util::Status key_pair_validation = ValidateKeyPair(
      public_key_->GetParameters().GetPublicExponent(),
      public_key_->GetModulus(token), *p_, *q_, *d_, *dp_, *dq_, *q_inv_);
  if (!key_pair_validation.ok()) {
    return key_pair_validation;
  }

  return RsaSsaPssPrivateKey(*public_key_, *p_, *q_, *dp_, *dq_, *d_,
                               *q_inv_);
}

bool RsaSsaPssPrivateKey::operator==(const Key& other) const {
  const RsaSsaPssPrivateKey* that =
      dynamic_cast<const RsaSsaPssPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetPublicKey() != that->GetPublicKey()) {
    return false;
  }
  if (p_ != that->p_) {
    return false;
  }
  if (q_ != that->q_) {
    return false;
  }
  if (dp_ != that->dp_) {
    return false;
  }
  if (dq_ != that->dq_) {
    return false;
  }
  if (d_ != that->d_) {
    return false;
  }
  return q_inv_ == that->q_inv_;
}

}  // namespace tink
}  // namespace crypto
