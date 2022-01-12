// Copyright 2021 Google LLC
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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pss_sign_key_manager.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_sign.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::RsaSsaPssVerifyBoringSsl;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPssKeyFormat;
using ::google::crypto::tink::JwtRsaSsaPssPrivateKey;
using ::google::crypto::tink::JwtRsaSsaPssPublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;

TEST(RawJwtRsaSsaPssSignKeyManagerTest, Basic) {
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(
      RawJwtRsaSsaPssSignKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey"));
}

JwtRsaSsaPssKeyFormat CreateKeyFormat(JwtRsaSsaPssAlgorithm algorithm,
                                      int modulus_size_in_bits,
                                      int public_exponent) {
  JwtRsaSsaPssKeyFormat key_format;
  key_format.set_algorithm(algorithm);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);

  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).ValueOrDie());

  return key_format;
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, ValidatePs256KeyFormat) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS256, 3072, RSA_F4);
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, ValidatePs512KeyFormat) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS512, 3072, RSA_F4);
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, KeyWithSmallModulusIsInvalid) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS256, 512, RSA_F4);
  key_format.set_modulus_size_in_bits(512);
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, ValidateKeyFormatUnkownHashDisallowed) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS_UNKNOWN, 3072, RSA_F4);
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

// Runs several sanity checks, checking if a given private key fits a format.
void CheckNewKey(const JwtRsaSsaPssPrivateKey& private_key,
                 const JwtRsaSsaPssKeyFormat& key_format) {
  JwtRsaSsaPssPublicKey public_key = private_key.public_key();

  EXPECT_THAT(private_key.version(), Eq(0));
  EXPECT_THAT(private_key.version(), Eq(public_key.version()));
  EXPECT_THAT(public_key.n().length(), Gt(0));
  EXPECT_THAT(public_key.e().length(), Gt(0));
  EXPECT_THAT(public_key.algorithm(), Eq(key_format.algorithm()));

  EXPECT_THAT(key_format.public_exponent(), Eq(public_key.e()));
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(public_key.n());
  ASSERT_THAT(n.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> d =
      internal::StringToBignum(private_key.d());
  ASSERT_THAT(d.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> p =
      internal::StringToBignum(private_key.p());
  ASSERT_THAT(p.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> q =
      internal::StringToBignum(private_key.q());
  ASSERT_THAT(q.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> dp =
      internal::StringToBignum(private_key.dp());
  ASSERT_THAT(dp.status(), IsOk());
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> dq =
      internal::StringToBignum(private_key.dq());
  ASSERT_THAT(dq.status(), IsOk());
  internal::SslUniquePtr<BN_CTX> ctx(BN_CTX_new());

  // Check n = p * q.
  auto n_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
  EXPECT_TRUE(BN_mul(n_calc.get(), p->get(), q->get(), ctx.get()));
  EXPECT_EQ(BN_cmp(n_calc.get(), n->get()), 0);

  // Check n size >= modulus_size_in_bits bit.
  EXPECT_GE(BN_num_bits(n->get()), key_format.modulus_size_in_bits());

  // dp = d mod (p - 1)
  auto pm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(p->get()));
  EXPECT_TRUE(BN_sub_word(pm1.get(), 1));
  auto dp_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
  EXPECT_TRUE(BN_mod(dp_calc.get(), d->get(), pm1.get(), ctx.get()));
  EXPECT_EQ(BN_cmp(dp_calc.get(), dp->get()), 0);

  // dq = d mod (q - 1)
  auto qm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(q->get()));
  EXPECT_TRUE(BN_sub_word(qm1.get(), 1));
  auto dq_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
  EXPECT_TRUE(BN_mod(dq_calc.get(), d->get(), qm1.get(), ctx.get()));
  EXPECT_EQ(BN_cmp(dq_calc.get(), dq->get()), 0);
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, CreatePs256KeyValid) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS256, 2048, RSA_F4);
  StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      RawJwtRsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key.status(), IsOk());
  CheckNewKey(*private_key, key_format);
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().ValidateKey(*private_key),
              IsOk());
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, CreatePs384KeyValid) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS384, 3072, RSA_F4);
  StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      RawJwtRsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key.status(), IsOk());
  CheckNewKey(*private_key, key_format);
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().ValidateKey(*private_key),
              IsOk());
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, CreatePs512KeyValid) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS512, 4096, RSA_F4);
  StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      RawJwtRsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key.status(), IsOk());
  CheckNewKey(*private_key, key_format);
  EXPECT_THAT(RawJwtRsaSsaPssSignKeyManager().ValidateKey(*private_key),
              IsOk());
}

// Check that in a bunch of CreateKey calls all generated primes are distinct.
TEST(RawJwtRsaSsaPssSignKeyManagerTest, CreateKeyAlwaysNewRsaPair) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS256, 2048, RSA_F4);
  absl::flat_hash_set<std::string> keys;
  // This test takes about a second per key.
  int num_generated_keys = 5;
  for (int i = 0; i < num_generated_keys; ++i) {
    StatusOr<JwtRsaSsaPssPrivateKey> key =
        RawJwtRsaSsaPssSignKeyManager().CreateKey(key_format);
    ASSERT_THAT(key.status(), IsOk());
    keys.insert(key->p());
    keys.insert(key->q());
  }
  EXPECT_THAT(keys, SizeIs(2 * num_generated_keys));
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, GetPublicKey) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS256, 2048, RSA_F4);
  StatusOr<JwtRsaSsaPssPrivateKey> key =
      RawJwtRsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());
  StatusOr<JwtRsaSsaPssPublicKey> public_key =
      RawJwtRsaSsaPssSignKeyManager().GetPublicKey(*key);
  ASSERT_THAT(public_key.status(), IsOk());
  EXPECT_THAT(public_key->version(), Eq(key->public_key().version()));
  EXPECT_THAT(public_key->n(), Eq(key->public_key().n()));
  EXPECT_THAT(public_key->e(), Eq(key->public_key().e()));
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, Create) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS256, 3072, RSA_F4);
  StatusOr<JwtRsaSsaPssPrivateKey> key =
      RawJwtRsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RawJwtRsaSsaPssSignKeyManager().GetPrimitive<PublicKeySign>(*key);
  ASSERT_THAT(signer.status(), IsOk());

  internal::RsaSsaPssParams params;
  params.sig_hash = subtle::HashType::SHA256;
  params.mgf1_hash = subtle::HashType::SHA256;
  params.salt_length = 32;
  util::StatusOr<std::unique_ptr<RsaSsaPssVerifyBoringSsl>> direct_verifier =
      subtle::RsaSsaPssVerifyBoringSsl::New(
          {key->public_key().n(), key->public_key().e()}, params);

  ASSERT_THAT(direct_verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> sig = (*signer)->Sign(message);
  EXPECT_THAT((*direct_verifier)->Verify(*sig, message), IsOk());
}

TEST(RawJwtRsaSsaPssSignKeyManagerTest, CreateWrongKey) {
  JwtRsaSsaPssKeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPssAlgorithm::PS256, 3072, RSA_F4);
  StatusOr<JwtRsaSsaPssPrivateKey> key =
      RawJwtRsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RawJwtRsaSsaPssSignKeyManager().GetPrimitive<PublicKeySign>(*key);
  ASSERT_THAT(signer.status(), IsOk());

  StatusOr<JwtRsaSsaPssPrivateKey> second_key =
      RawJwtRsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(second_key.status(), IsOk());

  internal::RsaSsaPssParams params;
  params.sig_hash = subtle::HashType::SHA256;
  params.mgf1_hash = subtle::HashType::SHA256;
  params.salt_length = 32;
  util::StatusOr<std::unique_ptr<RsaSsaPssVerifyBoringSsl>> direct_verifier =
      subtle::RsaSsaPssVerifyBoringSsl::New(
          {second_key->public_key().n(), second_key->public_key().e()}, params);

  ASSERT_THAT(direct_verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> sig = (*signer)->Sign(message);
  EXPECT_THAT((*direct_verifier)->Verify(*sig, message), Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
