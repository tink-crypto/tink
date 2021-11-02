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

#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::IsEmpty;
using ::testing::Not;

constexpr int kSslSuccess = 1;

// Utility function to create an RSA key pair.
util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> GetKeyPair(
    size_t modulus_size_in_bits) {
  RsaPublicKey public_key;
  RsaPrivateKey private_key;
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  util::Status res =
      NewRsaKeyPair(modulus_size_in_bits, e.get(), &private_key, &public_key);
  if (!res.ok()) {
    return res;
  }
  return {{public_key, private_key}};
}

TEST(RsaUtilTest, BasicSanityChecks) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  const auto& [public_key, private_key] = *keys;

  EXPECT_THAT(private_key.n, Not(IsEmpty()));
  EXPECT_THAT(private_key.e, Not(IsEmpty()));
  EXPECT_THAT(private_key.d, Not(IsEmpty()));

  EXPECT_THAT(private_key.p, Not(IsEmpty()));
  EXPECT_THAT(private_key.q, Not(IsEmpty()));
  EXPECT_THAT(private_key.dp, Not(IsEmpty()));
  EXPECT_THAT(private_key.dq, Not(IsEmpty()));
  EXPECT_THAT(private_key.crt, Not(IsEmpty()));

  EXPECT_THAT(public_key.n, Not(IsEmpty()));
  EXPECT_THAT(public_key.e, Not(IsEmpty()));

  EXPECT_EQ(public_key.n, private_key.n);
  EXPECT_EQ(public_key.e, private_key.e);
}

TEST(RsaUtilTest, FailsOnLargeE) {
  // OpenSSL requires the "e" value to be at most 32 bits.
  RsaPublicKey public_key;
  RsaPrivateKey private_key;

  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), 1L << 33);
  EXPECT_THAT(NewRsaKeyPair(/*modulus_size_in_bits=*/2048, e.get(),
                            &private_key, &public_key),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(RsaUtilTest, KeyIsWellFormed) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  const auto& [public_key, private_key] = *keys;

  util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(private_key.n);
  ASSERT_THAT(n.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> d =
      internal::StringToBignum(util::SecretDataAsStringView(private_key.d));
  ASSERT_THAT(d.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> p =
      internal::StringToBignum(util::SecretDataAsStringView(private_key.p));
  ASSERT_THAT(p.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> q =
      internal::StringToBignum(util::SecretDataAsStringView(private_key.q));
  ASSERT_THAT(q.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> dp =
      internal::StringToBignum(util::SecretDataAsStringView(private_key.dp));
  ASSERT_THAT(dp.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> dq =
      internal::StringToBignum(util::SecretDataAsStringView(private_key.dq));
  ASSERT_THAT(dq.status(), IsOk());
  internal::SslUniquePtr<BN_CTX> ctx(BN_CTX_new());

  // Check n = p * q.
  {
    auto n_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
    ASSERT_EQ(BN_mul(n_calc.get(), p->get(), q->get(), ctx.get()), kSslSuccess);
    EXPECT_EQ(BN_equal_consttime(n_calc.get(), n->get()), kSslSuccess);
  }

  // Check n size >= 2048 bit.
  EXPECT_GE(BN_num_bits(n->get()), 2048);

  // dp = d mod (p - 1)
  {
    auto pm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(p->get()));
    ASSERT_EQ(BN_sub_word(pm1.get(), /*w=*/1), kSslSuccess);
    auto dp_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
    ASSERT_EQ(BN_mod(dp_calc.get(), d->get(), pm1.get(), ctx.get()),
              kSslSuccess);
    EXPECT_EQ(BN_equal_consttime(dp_calc.get(), dp->get()), kSslSuccess);
  }

  // dq = d mod (q - 1)
  {
    auto qm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(q->get()));
    ASSERT_EQ(BN_sub_word(qm1.get(), /*w=*/1), kSslSuccess);
    auto dq_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
    ASSERT_EQ(BN_mod(dq_calc.get(), d->get(), qm1.get(), ctx.get()),
              kSslSuccess);
    EXPECT_EQ(BN_equal_consttime(dq_calc.get(), dq->get()), kSslSuccess);
  }
}

TEST(RsaUtilTest, GeneratesDifferentPrivateKeys) {
  RsaPublicKey public_key;
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);

  std::vector<RsaPrivateKey> private_keys;
  std::generate_n(std::back_inserter(private_keys), 4, [&]() {
    RsaPrivateKey private_key;
    EXPECT_THAT(NewRsaKeyPair(/*modulus_size_in_bits=*/2048, e.get(),
                              &private_key, &public_key),
                IsOk());
    return private_key;
  });

  for (int i = 0; i < private_keys.size() - 1; i++) {
    for (int j = i + 1; j < private_keys.size(); j++) {
      // The only field that should be equal.
      EXPECT_EQ(private_keys[i].e, private_keys[j].e);
      EXPECT_NE(private_keys[i].n, private_keys[j].n);
      EXPECT_NE(private_keys[i].d, private_keys[j].d);
      EXPECT_NE(private_keys[i].p, private_keys[j].p);
      EXPECT_NE(private_keys[i].q, private_keys[j].q);
      EXPECT_NE(private_keys[i].dp, private_keys[j].dp);
      EXPECT_NE(private_keys[i].dq, private_keys[j].dq);
      EXPECT_NE(private_keys[i].crt, private_keys[j].crt);
    }
  }
}

TEST(RsaUtilTest, ValidateRsaModulusSize) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  {
    const auto& [public_key, private_key] = *keys;

    util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
        internal::StringToBignum(private_key.n);
    EXPECT_THAT(ValidateRsaModulusSize(BN_num_bits(n->get())), IsOk());
  }
  keys = GetKeyPair(/*modulus_size_in_bits=*/1024);
  ASSERT_THAT(keys.status(), IsOk());
  {
    const auto& [public_key, private_key] = *keys;
    util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
        internal::StringToBignum(private_key.n);
    EXPECT_THAT(ValidateRsaModulusSize(BN_num_bits(n->get())), Not(IsOk()));
  }
}

TEST(RsaUtilTest, ValidateRsaPublicExponent) {
  internal::SslUniquePtr<BIGNUM> e_bn(BN_new());

  // Failure scenario.
  const std::vector<BN_ULONG> invalid_exponents = {2, 3, 4, 65536, 65538};
  for (const BN_ULONG exponent : invalid_exponents) {
    BN_set_word(e_bn.get(), exponent);
    util::StatusOr<std::string> e_str =
        internal::BignumToString(e_bn.get(), BN_num_bytes(e_bn.get()));
    ASSERT_THAT(e_str.status(), IsOk());
    EXPECT_THAT(ValidateRsaPublicExponent(*e_str), Not(IsOk()));
  }

  // Successful case.
  BN_set_word(e_bn.get(), RSA_F4);
  util::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn.get(), BN_num_bytes(e_bn.get()));
  ASSERT_THAT(e_str.status(), IsOk());
  EXPECT_THAT(ValidateRsaPublicExponent(*e_str), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
