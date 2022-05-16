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

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
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
// 2048 bits modulus.
constexpr absl::string_view k2048BitRsaModulus =
    "b5a5651bc2e15ce31d789f0984053a2ea0cf8f964a78068c45acfdf078c57fd62d5a287c32"
    "f3baa879f5dfea27d7a3077c9d3a2a728368c3d90164690c3d82f660ffebc7f13fed454eb5"
    "103df943c10dc32ec60b0d9b6e307bfd7f9b943e0dc3901e42501765365f7286eff2f1f728"
    "774aa6a371e108a3a7dd00d7bcd4c1a186c2865d4b370ea38cc89c0b23b318dbcafbd872b4"
    "f9b833dfb2a4ca7fcc23298020044e8130bfe930adfb3e5cab8d324547adf4b2ce34d7cea4"
    "298f0b613d85f2bf1df03da44aee0784a1a20a15ee0c38a0f8e84962f1f61b18bd43781c73"
    "85f3c2b8e2aebd3c560b4faad208ad3938bad27ddda9ed9e933dba0880212dd9e28d";

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
  const RsaPublicKey& public_key = keys->first;
  const RsaPrivateKey& private_key = keys->second;

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
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaUtilTest, KeyIsWellFormed) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  const RsaPrivateKey& private_key = keys->second;

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
    EXPECT_EQ(BN_cmp(n_calc.get(), n->get()), 0);
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
    EXPECT_EQ(BN_cmp(dp_calc.get(), dp->get()), 0);
  }

  // dq = d mod (q - 1)
  {
    auto qm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(q->get()));
    ASSERT_EQ(BN_sub_word(qm1.get(), /*w=*/1), kSslSuccess);
    auto dq_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
    ASSERT_EQ(BN_mod(dq_calc.get(), d->get(), qm1.get(), ctx.get()),
              kSslSuccess);
    EXPECT_EQ(BN_cmp(dq_calc.get(), dq->get()), 0);
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
    const RsaPrivateKey& private_key = keys->second;

    util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
        internal::StringToBignum(private_key.n);
    EXPECT_THAT(ValidateRsaModulusSize(BN_num_bits(n->get())), IsOk());
  }
  keys = GetKeyPair(/*modulus_size_in_bits=*/1024);
  ASSERT_THAT(keys.status(), IsOk());
  {
    const RsaPrivateKey& private_key = keys->second;

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

// Checks if a BIGNUM is equal to a string value.
void ExpectBignumEquals(const BIGNUM* bn, absl::string_view data) {
  util::StatusOr<std::string> converted =
      internal::BignumToString(bn, BN_num_bytes(bn));
  ASSERT_THAT(converted.status(), IsOk());
  EXPECT_EQ(*converted, data);
}

// Checks if a BIGNUM is equal to a SecretData value.
void ExpectBignumEquals(const BIGNUM* bn, const util::SecretData& data) {
  internal::ExpectBignumEquals(bn, util::SecretDataAsStringView(data));
}

TEST(RsaUtilTest, GetRsaModAndExponents) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  const RsaPrivateKey& private_key = keys->second;
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  util::Status result = GetRsaModAndExponents(private_key, rsa.get());
  ASSERT_THAT(result, IsOk());
  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  RSA_get0_key(rsa.get(), &n, &e, &d);
  ExpectBignumEquals(n, private_key.n);
  ExpectBignumEquals(e, private_key.e);
  ExpectBignumEquals(d, private_key.d);
}

TEST(RsaUtilTest, GetRsaPrimeFactors) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  const RsaPrivateKey& private_key = keys->second;
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  util::Status result = GetRsaPrimeFactors(private_key, rsa.get());
  ASSERT_THAT(result, IsOk());
  const BIGNUM* p = nullptr;
  const BIGNUM* q = nullptr;
  RSA_get0_factors(rsa.get(), &p, &q);
  ExpectBignumEquals(p, private_key.p);
  ExpectBignumEquals(q, private_key.q);
}

TEST(RsaUtilTest, GetRsaCrtParams) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  const RsaPrivateKey& private_key = keys->second;
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  const BIGNUM* dp = nullptr;
  const BIGNUM* dq = nullptr;
  const BIGNUM* crt = nullptr;
  util::Status result = GetRsaCrtParams(private_key, rsa.get());
  ASSERT_THAT(result, IsOk());
  RSA_get0_crt_params(rsa.get(), &dp, &dq, &crt);
  ExpectBignumEquals(dp, private_key.dp);
  ExpectBignumEquals(dq, private_key.dq);
  ExpectBignumEquals(crt, private_key.crt);
}

TEST(RsaUtilTest, CopiesRsaPrivateKey) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  const RsaPrivateKey& private_key = keys->second;

  util::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsa(private_key);
  EXPECT_TRUE(rsa_result.ok());
  internal::SslUniquePtr<RSA> rsa = std::move(rsa_result).value();
  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  RSA_get0_key(rsa.get(), &n, &e, &d);
  const BIGNUM* p = nullptr;
  const BIGNUM* q = nullptr;
  RSA_get0_factors(rsa.get(), &p, &q);
  ExpectBignumEquals(n, private_key.n);
  ExpectBignumEquals(e, private_key.e);
  ExpectBignumEquals(d, private_key.d);
  ExpectBignumEquals(p, private_key.p);
  ExpectBignumEquals(q, private_key.q);
}

TEST(RsaUtilTest, CopiesRsaPublicKey) {
  util::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys.status(), IsOk());
  const RsaPublicKey& public_key = keys->first;

  util::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPublicKeyToRsa(public_key);
  EXPECT_TRUE(rsa_result.ok());
  internal::SslUniquePtr<RSA> rsa = std::move(rsa_result).value();

  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  RSA_get0_key(rsa.get(), &n, &e, /*d=*/nullptr);
  ExpectBignumEquals(n, public_key.n);
  ExpectBignumEquals(e, public_key.e);
}

// Utility function that creates an RSA public key with the given modulus
// `n_hex` and exponent `exp`.
util::StatusOr<internal::SslUniquePtr<RSA>> NewRsaPublicKey(
    absl::string_view n_hex, uint64_t exp) {
  internal::SslUniquePtr<RSA> key(RSA_new());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> n_bn =
      internal::StringToBignum(absl::HexStringToBytes(n_hex));
  if (!n_bn.ok()) {
    return n_bn.status();
  }
  internal::SslUniquePtr<BIGNUM> n = *std::move(n_bn);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), exp);
  if (RSA_set0_key(key.get(), n.get(), e.get(), /*d=*/nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal, "RSA_set0_key failed");
  }
  // RSA_set0_key takes ownership of the arguments.
  n.release();
  e.release();
  return std::move(key);
}

TEST(RsaUtilTest, RsaCheckPublicKeyNullKey) {
  EXPECT_THAT(RsaCheckPublicKey(nullptr), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyMissingExponentAndModule) {
  internal::SslUniquePtr<RSA> key(RSA_new());
  EXPECT_THAT(RsaCheckPublicKey(key.get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyValid) {
  util::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(k2048BitRsaModulus, RSA_F4);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), IsOk());
}

TEST(RsaUtilTest, RsaCheckPublicKeyExponentTooLarge) {
  // Invalid exponent of 34 bits.
  constexpr uint64_t kExponentTooLarge = 0x200000000;
  util::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(k2048BitRsaModulus, kExponentTooLarge);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyExponentTooSmall) {
  constexpr uint64_t kExponentEqualsToOne = 0x1;
  util::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(k2048BitRsaModulus, kExponentEqualsToOne);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyExponentNotOdd) {
  constexpr uint64_t kExponentNotOdd = 0x20000000;
  util::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(k2048BitRsaModulus, kExponentNotOdd);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyModulusTooLarge) {
  // Get 1 byte more than 16384 bits (2048 bytes).
  std::string too_large_modulus = subtle::Random::GetRandomBytes(2049);
  if (too_large_modulus[0] == '\0') {
    too_large_modulus[0] = 0x01;
  }
  util::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(absl::BytesToHexString(too_large_modulus), RSA_F4);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyModulusSmallerThanExp) {
  constexpr absl::string_view kModulusSmallerThanExp = "1001";
  util::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(kModulusSmallerThanExp, RSA_F4);
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
