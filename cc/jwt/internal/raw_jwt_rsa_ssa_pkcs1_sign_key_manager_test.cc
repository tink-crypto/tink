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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pkcs1_sign_key_manager.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/internal/raw_jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::RsaSsaPkcs1VerifyBoringSsl;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::JwtRsaSsaPkcs1PrivateKey;
using ::google::crypto::tink::JwtRsaSsaPkcs1PublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

TEST(JwtRsaSsaPkcsSignKeyManagerTest, Basic) {
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(
      RawJwtRsaSsaPkcs1SignKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey"));
}

JwtRsaSsaPkcs1KeyFormat CreateKeyFormat(JwtRsaSsaPkcs1Algorithm algorithm,
                                        int modulus_size_in_bits,
                                        int public_exponent) {
  JwtRsaSsaPkcs1KeyFormat key_format;
  key_format.set_algorithm(algorithm);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).ValueOrDie());
  return key_format;
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, ValidateKeyFormatRs256) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 3072, RSA_F4);
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, ValidateKeyFormatRs384) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS384, 3072, RSA_F4);
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, ValidateKeyFormatRs512) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS512, 3072, RSA_F4);
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, KeyFormatWithUnknownAlgorithmIsInvalid) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS_UNKNOWN, 3072, RSA_F4);
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, KeyFormatWithSmallModulusIsInvalid) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2047, RSA_F4);
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

// Checks whether given key is compatible with the given format.
void CheckNewKey(const JwtRsaSsaPkcs1PrivateKey& private_key,
                 const JwtRsaSsaPkcs1KeyFormat& key_format) {
  RawJwtRsaSsaPkcs1SignKeyManager key_manager;
  JwtRsaSsaPkcs1PublicKey public_key = private_key.public_key();
  EXPECT_EQ(0, private_key.version());
  EXPECT_TRUE(private_key.has_public_key());
  EXPECT_EQ(0, public_key.version());
  EXPECT_GT(public_key.n().length(), 0);
  EXPECT_GT(public_key.e().length(), 0);
  EXPECT_EQ(public_key.algorithm(), key_format.algorithm());
  EXPECT_EQ(key_format.public_exponent(), public_key.e());

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
  EXPECT_TRUE(BN_equal_consttime(n_calc.get(), n->get()));

  // Check n size >= modulus_size_in_bits bit.
  EXPECT_GE(BN_num_bits(n->get()), key_format.modulus_size_in_bits());

  // dp = d mod (p - 1)
  auto pm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(p->get()));
  EXPECT_TRUE(BN_sub_word(pm1.get(), 1));
  auto dp_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
  EXPECT_TRUE(BN_mod(dp_calc.get(), d->get(), pm1.get(), ctx.get()));
  EXPECT_TRUE(BN_equal_consttime(dp_calc.get(), dp->get()));

  // dq = d mod (q - 1)
  auto qm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(q->get()));
  EXPECT_TRUE(BN_sub_word(qm1.get(), 1));
  auto dq_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
  EXPECT_TRUE(BN_mod(dq_calc.get(), d->get(), qm1.get(), ctx.get()));

  EXPECT_TRUE(BN_equal_consttime(dq_calc.get(), dq->get()));
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, CreateRs256Key) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 3072, RSA_F4);
  StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      RawJwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key.status(), IsOk());
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().ValidateKey(*private_key),
              IsOk());
  CheckNewKey(*private_key, key_format);
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, CreateSmallRs256Key) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);

  StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      RawJwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key.status(), IsOk());
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().ValidateKey(*private_key),
              IsOk());
  CheckNewKey(*private_key, key_format);
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, CreateKeyLargeRs512Key) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS512, 4096, RSA_F4);

  StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      RawJwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key.status(), IsOk());
  EXPECT_THAT(RawJwtRsaSsaPkcs1SignKeyManager().ValidateKey(*private_key),
              IsOk());
  CheckNewKey(*private_key, key_format);
}

// Check that in a bunch of CreateKey calls all generated primes are distinct.
TEST(JwtRsaSsaPkcs1SignKeyManagerTest, CreateKeyAlwaysNewRsaPair) {
  absl::flat_hash_set<std::string> keys;
  // This test takes about a second per key.
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);
  int num_generated_keys = 5;
  for (int i = 0; i < num_generated_keys; ++i) {
    StatusOr<JwtRsaSsaPkcs1PrivateKey> key =
        RawJwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
    ASSERT_THAT(key.status(), IsOk());
    keys.insert(key->p());
    keys.insert(key->q());
  }
  EXPECT_THAT(keys, SizeIs(2 * num_generated_keys));
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, GetPublicKey) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 2048, RSA_F4);
  StatusOr<JwtRsaSsaPkcs1PrivateKey> key =
      RawJwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());
  StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      RawJwtRsaSsaPkcs1SignKeyManager().GetPublicKey(*key);
  ASSERT_THAT(public_key.status(), IsOk());
  EXPECT_THAT(public_key->version(), Eq(key->public_key().version()));
  EXPECT_THAT(public_key->algorithm(), Eq(key->public_key().algorithm()));
  EXPECT_THAT(public_key->n(), Eq(key->public_key().n()));
  EXPECT_THAT(public_key->e(), Eq(key->public_key().e()));
}

TEST(JwtRsaSsaPkcs1SignKeyManagerTest, Create) {
  JwtRsaSsaPkcs1KeyFormat key_format =
      CreateKeyFormat(JwtRsaSsaPkcs1Algorithm::RS256, 3072, RSA_F4);
  StatusOr<JwtRsaSsaPkcs1PrivateKey> key =
      RawJwtRsaSsaPkcs1SignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key.status(), IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RawJwtRsaSsaPkcs1SignKeyManager().GetPrimitive<PublicKeySign>(*key);
  ASSERT_THAT(signer.status(), IsOk());

  util::StatusOr<std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl>> direct_verifier =
      subtle::RsaSsaPkcs1VerifyBoringSsl::New(
          {key->public_key().n(), key->public_key().e()},
          {subtle::HashType::SHA256});
  ASSERT_THAT(direct_verifier.status(), IsOk());

  std::string message = "Some message";
  util::StatusOr<std::string> sig = (*signer)->Sign(message);
  ASSERT_THAT(sig.status(), IsOk());
  EXPECT_THAT((*direct_verifier)->Verify(*sig, message), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
