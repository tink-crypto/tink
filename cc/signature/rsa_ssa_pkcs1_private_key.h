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

#ifndef TINK_SIGNATURE_RSA_SSA_PKCS1_PRIVATE_KEY_H_
#define TINK_SIGNATURE_RSA_SSA_PKCS1_PRIVATE_KEY_H_

#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class RsaSsaPkcs1PrivateKey : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  RsaSsaPkcs1PrivateKey(const RsaSsaPkcs1PrivateKey& other) = default;
  RsaSsaPkcs1PrivateKey& operator=(const RsaSsaPkcs1PrivateKey& other) =
      default;
  RsaSsaPkcs1PrivateKey(RsaSsaPkcs1PrivateKey&& other) = default;
  RsaSsaPkcs1PrivateKey& operator=(RsaSsaPkcs1PrivateKey&& other) = default;

  // Creates RsaSsaPkcs1 private key instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty private key builder.
    Builder() = default;

    Builder& SetPublicKey(const RsaSsaPkcs1PublicKey& public_key);
    Builder& SetPrimeP(const RestrictedBigInteger& p);
    Builder& SetPrimeQ(const RestrictedBigInteger& q);
    Builder& SetPrimeExponentP(const RestrictedBigInteger& dp);
    Builder& SetPrimeExponentQ(const RestrictedBigInteger& dq);
    Builder& SetPrivateExponent(const RestrictedBigInteger& d);
    Builder& SetCrtCoefficient(const RestrictedBigInteger& q_inv);

    // Creates RsaSsaPkcs1 private key object from this builder.
    util::StatusOr<RsaSsaPkcs1PrivateKey> Build(PartialKeyAccessToken token);

   private:
    absl::optional<RsaSsaPkcs1PublicKey> public_key_;
    absl::optional<RestrictedBigInteger> p_;
    absl::optional<RestrictedBigInteger> q_;
    absl::optional<RestrictedBigInteger> dp_;
    absl::optional<RestrictedBigInteger> dq_;
    absl::optional<RestrictedBigInteger> d_;
    absl::optional<RestrictedBigInteger> q_inv_;
  };

  const RestrictedBigInteger& GetPrimeP(PartialKeyAccessToken token) const {
    return p_;
  }

  const RestrictedBigInteger& GetPrimeQ(PartialKeyAccessToken token) const {
    return q_;
  }

  const RestrictedBigInteger& GetPrivateExponent() const { return d_; }

  const RestrictedBigInteger& GetPrimeExponentP() const { return dp_; }

  const RestrictedBigInteger& GetPrimeExponentQ() const { return dq_; }

  const RestrictedBigInteger& GetCrtCoefficient() const { return q_inv_; }

  const RsaSsaPkcs1PublicKey& GetPublicKey() const override {
    return public_key_;
  }

  bool operator==(const Key& other) const override;

 private:
  explicit RsaSsaPkcs1PrivateKey(const RsaSsaPkcs1PublicKey& public_key,
                                 const RestrictedBigInteger& p,
                                 const RestrictedBigInteger& q,
                                 const RestrictedBigInteger& dp,
                                 const RestrictedBigInteger& dq,
                                 const RestrictedBigInteger& d,
                                 const RestrictedBigInteger& q_inv)
      : public_key_(public_key),
        p_(p),
        q_(q),
        dp_(dp),
        dq_(dq),
        d_(d),
        q_inv_(q_inv) {}

  RsaSsaPkcs1PublicKey public_key_;
  RestrictedBigInteger p_;
  RestrictedBigInteger q_;
  RestrictedBigInteger dp_;
  RestrictedBigInteger dq_;
  RestrictedBigInteger d_;
  RestrictedBigInteger q_inv_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_RSA_SSA_PKCS1_PRIVATE_KEY_H_
