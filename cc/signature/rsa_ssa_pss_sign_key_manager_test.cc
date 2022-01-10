// Copyright 2018 Google LLC
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

#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_sign.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/rsa_ssa_pss.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::RsaSsaPssKeyFormat;
using ::google::crypto::tink::RsaSsaPssPrivateKey;
using ::google::crypto::tink::RsaSsaPssPublicKey;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;

TEST(RsaSsaPssSignKeyManagerTest, Basic) {
  EXPECT_THAT(RsaSsaPssSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RsaSsaPssSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(RsaSsaPssSignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey"));
}

RsaSsaPssKeyFormat CreateKeyFormat(HashType sig_hash, HashType mgf1_hash,
                                   int salt_length, int modulus_size_in_bits,
                                   int public_exponent) {
  RsaSsaPssKeyFormat key_format;
  auto params = key_format.mutable_params();
  params->set_sig_hash(sig_hash);
  params->set_mgf1_hash(mgf1_hash);
  params->set_salt_length(salt_length);
  key_format.set_modulus_size_in_bits(modulus_size_in_bits);

  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);
  key_format.set_public_exponent(
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).ValueOrDie());

  return key_format;
}

RsaSsaPssKeyFormat ValidKeyFormat() {
  return CreateKeyFormat(HashType::SHA256, HashType::SHA256, 32, 3072, RSA_F4);
}

TEST(RsaSsaPssSignKeyManagerTest, ValidateKeyFormat) {
  EXPECT_THAT(RsaSsaPssSignKeyManager().ValidateKeyFormat(ValidKeyFormat()),
              IsOk());
}

TEST(RsaSsaPssSignKeyManagerTest, ValidateKeyFormatSha512Allowed) {
  RsaSsaPssKeyFormat key_format = ValidKeyFormat();
  key_format.mutable_params()->set_sig_hash(HashType::SHA512);
  key_format.mutable_params()->set_mgf1_hash(HashType::SHA512);
  EXPECT_THAT(RsaSsaPssSignKeyManager().ValidateKeyFormat(ValidKeyFormat()),
              IsOk());
}

TEST(RsaSsaPssSignKeyManagerTest, ValidateKeyFormatSha1Disallowed) {
  RsaSsaPssKeyFormat key_format = ValidKeyFormat();
  key_format.mutable_params()->set_sig_hash(HashType::SHA1);
  EXPECT_THAT(RsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RsaSsaPssSignKeyManagerTest, ValidateKeyFormatSmallModulusDisallowed) {
  RsaSsaPssKeyFormat key_format = ValidKeyFormat();
  key_format.set_modulus_size_in_bits(512);
  EXPECT_THAT(RsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RsaSsaPssSignKeyManagerTest, ValidateKeyFormatHashMismatchDisallowed) {
  RsaSsaPssKeyFormat key_format = ValidKeyFormat();
  key_format.mutable_params()->set_sig_hash(HashType::SHA512);
  key_format.mutable_params()->set_mgf1_hash(HashType::SHA256);
  EXPECT_THAT(RsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RsaSsaPssSignKeyManagerTest, ValidateKeyFormatHashMismatchDisallowed2) {
  RsaSsaPssKeyFormat key_format = ValidKeyFormat();
  key_format.mutable_params()->set_sig_hash(HashType::SHA256);
  key_format.mutable_params()->set_mgf1_hash(HashType::SHA512);
  EXPECT_THAT(RsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RsaSsaPssSignKeyManagerTest, ValidateKeyFormatUnkownHashDisallowed) {
  RsaSsaPssKeyFormat key_format = ValidKeyFormat();
  key_format.mutable_params()->set_sig_hash(HashType::UNKNOWN_HASH);
  key_format.mutable_params()->set_mgf1_hash(HashType::UNKNOWN_HASH);
  EXPECT_THAT(RsaSsaPssSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

// Runs several sanity checks, checking if a given private key fits a format.
void CheckNewKey(const RsaSsaPssPrivateKey& private_key,
                 const RsaSsaPssKeyFormat& key_format) {
  RsaSsaPssPublicKey public_key = private_key.public_key();

  EXPECT_THAT(private_key.version(), Eq(0));
  EXPECT_THAT(private_key.version(), Eq(public_key.version()));
  EXPECT_THAT(public_key.n().length(), Gt(0));
  EXPECT_THAT(public_key.e().length(), Gt(0));
  EXPECT_THAT(public_key.params().sig_hash(),
              Eq(key_format.params().sig_hash()));
  EXPECT_THAT(public_key.params().mgf1_hash(),
              Eq(key_format.params().mgf1_hash()));
  EXPECT_THAT(public_key.params().salt_length(),
              Eq(key_format.params().salt_length()));

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

TEST(RsaSsaPssSignKeyManagerTest, CreateKey) {
  RsaSsaPssKeyFormat key_format = ValidKeyFormat();
  StatusOr<RsaSsaPssPrivateKey> private_key_or =
      RsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key_or.status(), IsOk());
  CheckNewKey(private_key_or.ValueOrDie(), key_format);
}

TEST(RsaSsaPssSignKeyManagerTest, CreateKeySmallKey) {
  RsaSsaPssKeyFormat key_format =
      CreateKeyFormat(HashType::SHA256, HashType::SHA256, 32, 3072, RSA_F4);

  StatusOr<RsaSsaPssPrivateKey> private_key_or =
      RsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key_or.status(), IsOk());
  CheckNewKey(private_key_or.ValueOrDie(), key_format);
}

TEST(RsaSsaPssSignKeyManagerTest, CreateKeyLargeKey) {
  RsaSsaPssKeyFormat key_format =
      CreateKeyFormat(HashType::SHA512, HashType::SHA512, 64, 4096, RSA_F4);

  StatusOr<RsaSsaPssPrivateKey> private_key_or =
      RsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(private_key_or.status(), IsOk());
  CheckNewKey(private_key_or.ValueOrDie(), key_format);
}

TEST(RsaSsaPssSignKeyManagerTest, CreateKeyValid) {
  StatusOr<RsaSsaPssPrivateKey> key_or =
      RsaSsaPssSignKeyManager().CreateKey(ValidKeyFormat());
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(RsaSsaPssSignKeyManager().ValidateKey(key_or.ValueOrDie()),
              IsOk());
}

// Check that in a bunch of CreateKey calls all generated primes are distinct.
TEST(RsaSsaPssSignKeyManagerTest, CreateKeyAlwaysNewRsaPair) {
  absl::flat_hash_set<std::string> keys;
  // This test takes about a second per key.
  int num_generated_keys = 5;
  for (int i = 0; i < num_generated_keys; ++i) {
    StatusOr<RsaSsaPssPrivateKey> key_or =
        RsaSsaPssSignKeyManager().CreateKey(ValidKeyFormat());
    ASSERT_THAT(key_or.status(), IsOk());
    keys.insert(key_or.ValueOrDie().p());
    keys.insert(key_or.ValueOrDie().q());
  }
  EXPECT_THAT(keys, SizeIs(2 * num_generated_keys));
}

TEST(RsaSsaPssSignKeyManagerTest, GetPublicKey) {
  StatusOr<RsaSsaPssPrivateKey> key_or =
      RsaSsaPssSignKeyManager().CreateKey(ValidKeyFormat());
  ASSERT_THAT(key_or.status(), IsOk());
  StatusOr<RsaSsaPssPublicKey> public_key_or =
      RsaSsaPssSignKeyManager().GetPublicKey(key_or.ValueOrDie());
  ASSERT_THAT(public_key_or.status(), IsOk());
  EXPECT_THAT(public_key_or.ValueOrDie().version(),
              Eq(key_or.ValueOrDie().public_key().version()));
  EXPECT_THAT(public_key_or.ValueOrDie().n(),
              Eq(key_or.ValueOrDie().public_key().n()));
  EXPECT_THAT(public_key_or.ValueOrDie().e(),
              Eq(key_or.ValueOrDie().public_key().e()));
}

TEST(RsaSsaPssSignKeyManagerTest, Create) {
  RsaSsaPssKeyFormat key_format =
      CreateKeyFormat(HashType::SHA256, HashType::SHA256, 32, 3072, RSA_F4);
  StatusOr<RsaSsaPssPrivateKey> key_or =
      RsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  RsaSsaPssPrivateKey key = key_or.ValueOrDie();

  auto signer_or = RsaSsaPssSignKeyManager().GetPrimitive<PublicKeySign>(key);
  ASSERT_THAT(signer_or.status(), IsOk());

  internal::RsaSsaPssParams params;
  params.sig_hash = subtle::HashType::SHA256;
  params.mgf1_hash = subtle::HashType::SHA256;
  params.salt_length = 32;
  auto direct_verifier_or = subtle::RsaSsaPssVerifyBoringSsl::New(
      {key.public_key().n(), key.public_key().e()}, params);

  ASSERT_THAT(direct_verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.ValueOrDie()->Verify(
                  signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
              IsOk());
}

TEST(RsaSsaPssSignKeyManagerTest, CreateWrongKey) {
  RsaSsaPssKeyFormat key_format =
      CreateKeyFormat(HashType::SHA256, HashType::SHA256, 32, 3072, RSA_F4);
  StatusOr<RsaSsaPssPrivateKey> key_or =
      RsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(key_or.status(), IsOk());
  RsaSsaPssPrivateKey key = key_or.ValueOrDie();

  auto signer_or = RsaSsaPssSignKeyManager().GetPrimitive<PublicKeySign>(key);

  StatusOr<RsaSsaPssPrivateKey> second_key_or =
      RsaSsaPssSignKeyManager().CreateKey(key_format);
  ASSERT_THAT(second_key_or.status(), IsOk());
  RsaSsaPssPrivateKey second_key = second_key_or.ValueOrDie();

  ASSERT_THAT(signer_or.status(), IsOk());

  internal::RsaSsaPssParams params;
  params.sig_hash = subtle::HashType::SHA256;
  params.mgf1_hash = subtle::HashType::SHA256;
  params.salt_length = 32;
  auto direct_verifier_or = subtle::RsaSsaPssVerifyBoringSsl::New(
      {second_key.public_key().n(), second_key.public_key().e()}, params);

  ASSERT_THAT(direct_verifier_or.status(), IsOk());

  std::string message = "Some message";
  EXPECT_THAT(direct_verifier_or.ValueOrDie()->Verify(
                  signer_or.ValueOrDie()->Sign(message).ValueOrDie(), message),
              Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
