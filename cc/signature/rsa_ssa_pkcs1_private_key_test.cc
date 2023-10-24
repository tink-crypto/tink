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

#include "tink/signature/rsa_ssa_pkcs1_private_key.h"

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
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
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
  RsaSsaPkcs1Parameters::HashType hash_type;
  RsaSsaPkcs1Parameters::Variant variant;
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

// Test vector from
// https://github.com/google/wycheproof/blob/master/testvectors/rsa_pkcs1_2048_test.json
constexpr absl::string_view k2048BitRsaModulus =
    "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-"
    "Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_"
    "ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_"
    "RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_"
    "tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_"
    "Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ";

constexpr absl::string_view kD =
    "GlAtDupse2niHVg5EB9wVFbtDvhS-0f-"
    "IQcfVMXzPIzrBmxi1yfjLSbFgTcyn4nTGVMlt5UmTBldhUcvdQfb0JYdKVH5NaJrNPCsJNFUkO"
    "ESiptxOJFbx9v6j-OWNXExxUOunJhQc2jZzrCMHGGYo-"
    "2nrqGFoOl2zULCLQDwA9nxnZbqTJr8v-"
    "FEHMyALPsGifWdgExqTk9ATBUXR0XtbLi8iO8LM7oNKoDjXkO8kPNQBS5yAW51sA01ejgcnA1G"
    "cGnKZgiHyYd2Y0n8xDRgtKpRa84Hnt2HuhZDB7dSwnftlSitO6C_"
    "GHc0ntO3lmpsJAEQQJv00PreDGj9rdhH_Q";

constexpr absl::string_view kP =
    "7BJc834xCi_0YmO5suBinWOQAF7IiRPU-3G9TdhWEkSYquupg9e6K9lC5k0iP-t6I69NYF7-"
    "6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ_-FdkYlwuGSNttMQBzjCiVy0-y0-"
    "Wm3rRnFIsAtd0RlZ24aN3bFTWJINIs";

constexpr absl::string_view kQ =
    "wnQqvNmJe9SwtnH5c_yCqPhKv1cF_4jdQZSGI6_p3KYNxlQzkHZ_"
    "6uvrU5V27ov6YbX8vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZ"
    "z3s4XdhiJBShgy-fKURvBQwtWmQHZJ3EGrcOI7PcwiyYc";

constexpr absl::string_view kDp =
    "lql5jSUCY0ALtidzQogWJ-B87N-RGHsBuJ_0cxQYinwg-ySAAVbSyF1WZujfbO_5-YBN362A_"
    "1dn3lbswCnHK_bHF9-fZNqvwprPnceQj5oK1n4g6JSZNsy6GNAhosT-"
    "uwQ0misgR8SQE4W25dDGkdEYsz-BgCsyrCcu8J5C-tU";

constexpr absl::string_view kDq =
    "BVT0GwuH9opFcis74M9KseFlA0wakQAquPKenvni2rb-57JFW6-0IDfp0vflM_"
    "NIoUdBL9cggL58JjP12ALJHDnmvOzj5nXlmZUDPFVzcCDa2eizDQS4KK37kwStVKEaNaT1BwmH"
    "asWxGCNrp2pNfJopHdlgexad4dGCOFaRmZ8";

constexpr absl::string_view kQInv =
    "HGQBidm_6MYjgzIQp2xCDG9E5ddg4lmRbOwq4rFWRWlg_ZXidHZgw4lWIlDwVQSc-"
    "rflwwOVSThKeiquscgk069wlIKoz5tYcCKgCx8HIttQ8zyybcIN0iRdUmXfYe4pg8k4whZ9zuE"
    "h_EtEecI35yjPYzq2CowOzQT85-O6pVk";

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

PrivateValues GetValidPrivateValues() {
  return PrivateValues{
      .p = RestrictedBigInteger(Base64WebSafeDecode(kP),
                                InsecureSecretKeyAccess::Get()),
      .q = RestrictedBigInteger(Base64WebSafeDecode(kQ),
                                InsecureSecretKeyAccess::Get()),
      .dp = RestrictedBigInteger(Base64WebSafeDecode(kDp),
                                 InsecureSecretKeyAccess::Get()),
      .dq = RestrictedBigInteger(Base64WebSafeDecode(kDq),
                                 InsecureSecretKeyAccess::Get()),
      .d = RestrictedBigInteger(Base64WebSafeDecode(kD),
                                InsecureSecretKeyAccess::Get()),
      .q_inv = RestrictedBigInteger(Base64WebSafeDecode(kQInv),
                                    InsecureSecretKeyAccess::Get())};
}

RsaSsaPkcs1PublicKey GetValidPublicKey() {
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4Str)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status()) << "Failed to create parameters.";

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  CHECK_OK(public_key.status()) << "Failed to create public key.";
  return *public_key;
}

std::string FlipFirstByte(absl::string_view str) {
  std::string res(str);
  res[0] = ~res[0];
  return res;
}

using RsaSsaPkcs1PrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1PrivateKeyTestSuite, RsaSsaPkcs1PrivateKeyTest,
    Values(TestCase{RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{RsaSsaPkcs1Parameters::HashType::kSha384,
                    RsaSsaPkcs1Parameters::Variant::kLegacy,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{RsaSsaPkcs1Parameters::HashType::kSha512,
                    RsaSsaPkcs1Parameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeySucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4Str)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyFromBoringSsl) {
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

  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(*e_str)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, /*modulus=*/BigInteger(*n_str),
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesModulus) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PublicKey> public_key_modified_modulus =
      RsaSsaPkcs1PublicKey::Create(
          public_key.GetParameters(),
          BigInteger(FlipFirstByte(Base64WebSafeDecode(k2048BitRsaModulus))),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key_modified_modulus, IsOk());

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_modulus =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeP) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_prime_p =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeQ) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_prime_q =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentP) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_prime_exponent_p =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentQ) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_prime_exponent_q =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrivateExponent) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_private_exponent =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesCrtCoefficient) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_crt_coefficient =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPublicKeyNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_public_key_set =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrimePNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_prime_p_set =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrimeQNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_prime_q_set =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrimeExponentPNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_prime_exponent_p_set =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrimeExponentQNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_prime_exponent_q_set =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateExponentNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_private_exponent_set =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, BuildCrtCoefficientNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_crt_coefficient_set =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, CreateMismatchedKeyPairFails) {
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4Str)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // Test value from
  // https://github.com/google/wycheproof/blob/master/testvectors/rsa_pkcs1_2048_test.json
  BigInteger mismatched_modulus(Base64WebSafeDecode(
      "3ZBFkDl4CMQxQyliPZATRThDJRsTuLPE_vVFmBEq8-sxxxEDxiWZUWdOU72Tp-NtGUcuR06-"
      "gChobZUpSE2Lr-pKBLoZVVZnYWyEeGcFlACcm8aj7-UidMumTHJHR9ftwZTk_"
      "t3jKjKJ2Uwxk25-"
      "ehXXVvVISS9bNFuSfoxhi91VCsshoXrhSDBDg9ubPHuqPkyL2OhEqITao-GNVpmMsy-"
      "brk1B1WoY3dQxPICJt16du5EoRwusmwh_thkoqw-"
      "MTIk2CwIImQCNCOi9MfkHqAfoBWrWgA3_357Z2WSpOefkgRS4SXhVGsuFyd-"
      "RlvPv9VKG1s1LOagiqKd2Ohggjw"));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, mismatched_modulus,
                                   /*id_requirement=*/0x02030400,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST_P(RsaSsaPkcs1PrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4Str)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<RsaSsaPkcs1PrivateKey> same_private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, DifferentPublicKeyNotEqual) {
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4Str)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key1 =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/0x02030400,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<RsaSsaPkcs1PublicKey> public_key2 =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/0x01030005,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key1 =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key1)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key1, IsOk());

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key2 =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST(RsaSsaPkcs1PrivateKeyTest, DifferentKeyTypesNotEqual) {
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4Str)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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
