// Copyright 2023 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/rsa_ssa_pss_private_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  RsaSsaPssParameters::HashType hash_type;
  RsaSsaPssParameters::Variant variant;
  int salt_length_in_bytes;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

struct PrivateValues {
  RestrictedBigInteger p;
  RestrictedBigInteger q;
  RestrictedBigInteger dp;
  RestrictedBigInteger dq;
  RestrictedBigInteger d;
  RestrictedBigInteger q_inv;
};

constexpr int kModulusSizeInBits = 2048;

// Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
constexpr absl::string_view k2048BitRsaModulus =
    "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-"
    "TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_"
    "LYywlAGZ21WSdS_"
    "PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-"
    "AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_"
    "aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q";

constexpr absl::string_view kD =
    "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfS"
    "NkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9U"
    "vqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnu"
    "ToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsu"
    "rY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2a"
    "hecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ";

constexpr absl::string_view kP =
    "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHf"
    "QP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8"
    "UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws";

constexpr absl::string_view kQ =
    "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_"
    "coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_"
    "ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s";

constexpr absl::string_view kDp =
    "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_"
    "MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_"
    "lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c";

constexpr absl::string_view kDq =
    "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9"
    "GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBy"
    "mXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots";

constexpr absl::string_view kQInv =
    "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqq"
    "abu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0o"
    "Yu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8";

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

PrivateValues GetValidPrivateValues() {
  return PrivateValues{
      /*p=*/RestrictedBigInteger(Base64WebSafeDecode(kP),
                                 InsecureSecretKeyAccess::Get()),
      /*q=*/
      RestrictedBigInteger(Base64WebSafeDecode(kQ),
                           InsecureSecretKeyAccess::Get()),
      /*dp=*/
      RestrictedBigInteger(Base64WebSafeDecode(kDp),
                           InsecureSecretKeyAccess::Get()),
      /*dq=*/
      RestrictedBigInteger(Base64WebSafeDecode(kDq),
                           InsecureSecretKeyAccess::Get()),
      /*d=*/
      RestrictedBigInteger(Base64WebSafeDecode(kD),
                           InsecureSecretKeyAccess::Get()),
      /*q_inv=*/
      RestrictedBigInteger(Base64WebSafeDecode(kQInv),
                           InsecureSecretKeyAccess::Get())};
}

RsaSsaPssPublicKey GetValidPublicKey() {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status()) << "Failed to create parameters.";

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status()) << "Failed to create public key.";
  return *public_key;
}

std::string FlipFirstByte(absl::string_view str) {
  std::string res(str);
  res[0] = ~res[0];
  return res;
}

using RsaSsaPssPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssPrivateKeyTestSuite, RsaSsaPssPrivateKeyTest,
    Values(TestCase{RsaSsaPssParameters::HashType::kSha256,
                    RsaSsaPssParameters::Variant::kTink,
                    /*salt_length_in_bytes*/ 0,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{RsaSsaPssParameters::HashType::kSha256,
                    RsaSsaPssParameters::Variant::kCrunchy,
                    /*salt_length_in_bytes*/ 32,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{RsaSsaPssParameters::HashType::kSha384,
                    RsaSsaPssParameters::Variant::kLegacy,
                    /*salt_length_in_bytes*/ 48,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{RsaSsaPssParameters::HashType::kSha512,
                    RsaSsaPssParameters::Variant::kNoPrefix,
                    /*salt_length_in_bytes*/ 64,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(RsaSsaPssPrivateKeyTest, BuildPrivateKeySucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  util::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrimeP(GetPartialKeyAccess()),
              Eq(private_values.p));
  EXPECT_THAT(private_key->GetPrimeQ(GetPartialKeyAccess()),
              Eq(private_values.q));
  EXPECT_THAT(private_key->GetPrimeExponentP(), Eq(private_values.dp));
  EXPECT_THAT(private_key->GetPrimeExponentQ(), Eq(private_values.dq));
  EXPECT_THAT(private_key->GetCrtCoefficient(), Eq(private_values.q_inv));
  EXPECT_THAT(private_key->GetPrivateExponent(), Eq(private_values.d));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateKeyFromBoringSsl) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  ASSERT_THAT(rsa, NotNull());

  // Set public exponent to 65537.
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), 65537);

  // Generate an RSA key pair and get the values.
  ASSERT_THAT(RSA_generate_key_ex(rsa.get(), 2048, e.get(), /*cb=*/nullptr),
              Eq(1));

  const BIGNUM *n_bn, *e_bn, *d_bn, *p_bn, *q_bn, *dp_bn, *dq_bn, *q_inv_bn;
  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);
  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);
  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &q_inv_bn);

  util::StatusOr<std::string> n_str =
      internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  ASSERT_THAT(n_str, IsOk());
  util::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  ASSERT_THAT(e_str, IsOk());
  util::StatusOr<std::string> d_str =
      internal::BignumToString(d_bn, BN_num_bytes(d_bn));
  ASSERT_THAT(d_str, IsOk());
  util::StatusOr<std::string> p_str =
      internal::BignumToString(p_bn, BN_num_bytes(p_bn));
  ASSERT_THAT(p_str, IsOk());
  util::StatusOr<std::string> q_str =
      internal::BignumToString(q_bn, BN_num_bytes(q_bn));
  ASSERT_THAT(q_str, IsOk());
  util::StatusOr<std::string> dp_str =
      internal::BignumToString(dp_bn, BN_num_bytes(dp_bn));
  ASSERT_THAT(dp_str, IsOk());
  util::StatusOr<std::string> dq_str =
      internal::BignumToString(dq_bn, BN_num_bytes(dq_bn));
  ASSERT_THAT(dq_str, IsOk());
  util::StatusOr<std::string> q_inv_str =
      internal::BignumToString(q_inv_bn, BN_num_bytes(q_inv_bn));
  ASSERT_THAT(q_inv_str, IsOk());

  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(*e_str))
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, /*modulus=*/BigInteger(*n_str),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedBigInteger(*p_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedBigInteger(*q_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedBigInteger(*dp_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedBigInteger(*dq_str, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedBigInteger(*d_str, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedBigInteger(*q_inv_str, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrimeP(GetPartialKeyAccess())
                  .GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(*p_str));
  EXPECT_THAT(private_key->GetPrimeQ(GetPartialKeyAccess())
                  .GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(*q_str));
  EXPECT_THAT(private_key->GetPrimeExponentP().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*dp_str));
  EXPECT_THAT(private_key->GetPrimeExponentQ().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*dq_str));
  EXPECT_THAT(private_key->GetCrtCoefficient().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*q_inv_str));
  EXPECT_THAT(private_key->GetPrivateExponent().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*d_str));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(""));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesModulus) {
  RsaSsaPssPublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPublicKey> public_key_modified_modulus =
      RsaSsaPssPublicKey::Create(
          public_key.GetParameters(),
          BigInteger(FlipFirstByte(Base64WebSafeDecode(k2048BitRsaModulus))),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key_modified_modulus, IsOk());

  util::StatusOr<RsaSsaPssPrivateKey> private_key_modified_modulus =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key_modified_modulus)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_modulus.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrimeP) {
  RsaSsaPssPublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_modified_prime_p =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kP)),
                                   InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_p.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrimeQ) {
  RsaSsaPssPublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_modified_prime_q =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kQ)),
                                   InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_q.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentP) {
  RsaSsaPssPublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_modified_prime_exponent_p =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kDp)),
                                   InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_exponent_p.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentQ) {
  RsaSsaPssPublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_modified_prime_exponent_q =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kDq)),
                                   InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_exponent_q.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrivateExponent) {
  RsaSsaPssPublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_modified_private_exponent =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kD)),
                                   InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_private_exponent.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesCrtCoefficient) {
  RsaSsaPssPublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_modified_crt_coefficient =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kQInv)),
                                   InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_crt_coefficient.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPublicKeyNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_no_public_key_set =
      RsaSsaPssPrivateKey::Builder()
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_public_key_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrimePNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_no_prime_p_set =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_p_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrimeQNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_no_prime_q_set =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_q_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrimeExponentPNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_no_prime_exponent_p_set =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_exponent_p_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrimeExponentQNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_no_prime_exponent_q_set =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_exponent_q_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildPrivateExponentNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_no_private_exponent_set =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_private_exponent_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, BuildCrtCoefficientNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key_no_crt_coefficient_set =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_crt_coefficient_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPssPrivateKeyTest, CreateMismatchedKeyPairFails) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // Test vector from
  // https://github.com/google/wycheproof/blob/master/testvectors/rsa_pss_2048_sha256_mgf1_32_test.json
  BigInteger mismatched_modulus(absl::HexStringToBytes(
      "00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637f974"
      "6d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92"
      "512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f"
      "17e1a029397a1fa26a8dce26f490ed81299615d9814c22da610428e09c7d9658594266f5"
      "c021d0fceca08d945a12be82de4d1ece6b4c03145b5d3495d4ed5411eb878daf05fd7afc"
      "3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9f85e7975005d"
      "9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf78202"
      "83f742b9d5"));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, mismatched_modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key.status(),
              StatusIs(absl::StatusCode ::kInvalidArgument));
}

TEST_P(RsaSsaPssPrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<RsaSsaPssPrivateKey> same_private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(same_private_key, IsOk());

  EXPECT_TRUE(*private_key == *same_private_key);
  EXPECT_TRUE(*same_private_key == *private_key);
  EXPECT_FALSE(*private_key != *same_private_key);
  EXPECT_FALSE(*same_private_key != *private_key);
}

TEST(RsaSsaPssPrivateKeyTest, DifferentPublicKeyNotEqual) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key1 = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<RsaSsaPssPublicKey> public_key2 = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/0x01030005, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key1 =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key1)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key1, IsOk());

  util::StatusOr<RsaSsaPssPrivateKey> private_key2 =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key2)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST(RsaSsaPssPrivateKeyTest, DifferentKeyTypesNotEqual) {
  util::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
