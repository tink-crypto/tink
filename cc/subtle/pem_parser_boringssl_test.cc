// Copyright 2018 Google Inc.
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
#include "tink/subtle/pem_parser_boringssl.h"

#include <memory>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class PemParserTest : public ::testing::Test {
 public:
  PemParserTest() : rsa_(RSA_new()) {}

  void SetUp() override {
    // Create a new RSA key and output to PEM.
    ASSERT_THAT(rsa_, testing::NotNull());

    bssl::UniquePtr<BIGNUM> e(BN_new());
    ASSERT_THAT(e, testing::NotNull());
    BN_set_word(e.get(), RSA_F4);

    // Generate a 2048 bits RSA key pair.
    EXPECT_EQ(RSA_generate_key_ex(rsa_.get(), 2048, e.get(), /*cb=*/nullptr), 1)
        << SubtleUtilBoringSSL::GetErrors();

    // Write keys to PEM.
    bssl::UniquePtr<BIO> pub_key_pem_bio(BIO_new(BIO_s_mem()));
    bssl::UniquePtr<BIO> prv_key_pem_bio(BIO_new(BIO_s_mem()));

    // Write in PEM format.
    EXPECT_EQ(PEM_write_bio_RSA_PUBKEY(pub_key_pem_bio.get(), rsa_.get()), 1)
        << SubtleUtilBoringSSL::GetErrors();
    EXPECT_EQ(
        PEM_write_bio_RSAPrivateKey(prv_key_pem_bio.get(), rsa_.get(),
                                    /*enc=*/nullptr, /*kstr=*/nullptr,
                                    /*klen=*/0, /*cb=*/nullptr, /*u=*/nullptr),
        1)
        << SubtleUtilBoringSSL::GetErrors();

    pem_rsa_pub_key_.resize(pub_key_pem_bio->num_write + 1);
    pem_rsa_prv_key_.resize(prv_key_pem_bio->num_write + 1);
    EXPECT_EQ(BIO_read(pub_key_pem_bio.get(), pem_rsa_pub_key_.data(),
                       pub_key_pem_bio->num_write),
              pub_key_pem_bio->num_write);
    EXPECT_EQ(BIO_read(prv_key_pem_bio.get(), pem_rsa_prv_key_.data(),
                       prv_key_pem_bio->num_write),
              prv_key_pem_bio->num_write);
  }

 protected:
  // PEM encoded 2048 bit RSA key pair.
  std::vector<char> pem_rsa_pub_key_;
  std::vector<char> pem_rsa_prv_key_;

  // Holds the RSA object.
  bssl::UniquePtr<RSA> rsa_;
};

// Corrupts `container` by modifying one the elements in the middle.
template <class ContainerType>
void Corrupt(ContainerType* container) {
  if (container->empty()) {
    return;
  }
  std::vector<char> corrupted(container->begin(), container->end());
  size_t pos = corrupted.size() / 2;
  corrupted[pos] ^= 1;
  container->assign(corrupted.begin(), corrupted.end());
}

// Test we can correctly parse an RSA public key.
TEST_F(PemParserTest, ReadRsaPublicKey) {
  auto key_statusor = PemParser::ParseRsaPublicKey(
      absl::string_view(pem_rsa_pub_key_.data(), pem_rsa_pub_key_.size()));
  ASSERT_TRUE(key_statusor.ok()) << SubtleUtilBoringSSL::GetErrors();

  // Verify exponent and modulus are correctly set.
  auto key = std::move(key_statusor.ValueOrDie());
  const BIGNUM *e_bn, *n_bn;
  RSA_get0_key(rsa_.get(), &n_bn, &e_bn, nullptr);
  EXPECT_EQ(key->e,
            SubtleUtilBoringSSL::bn2str(e_bn, BN_num_bytes(e_bn)).ValueOrDie());
  EXPECT_EQ(key->n,
            SubtleUtilBoringSSL::bn2str(n_bn, BN_num_bytes(n_bn)).ValueOrDie());
}

// Test we can correctly parse an RSA private key.
TEST_F(PemParserTest, ReadRsaPrivatekey) {
  auto key_statusor = PemParser::ParseRsaPrivateKey(
      absl::string_view(pem_rsa_prv_key_.data(), pem_rsa_prv_key_.size()));
  ASSERT_TRUE(key_statusor.ok()) << SubtleUtilBoringSSL::GetErrors();

  // Verify exponents and modulus.
  auto key = std::move(key_statusor.ValueOrDie());
  const BIGNUM *e_bn, *n_bn, *d_bn;
  RSA_get0_key(rsa_.get(), &n_bn, &e_bn, &d_bn);
  EXPECT_EQ(key->e,
            SubtleUtilBoringSSL::bn2str(e_bn, BN_num_bytes(e_bn)).ValueOrDie());
  EXPECT_EQ(key->n,
            SubtleUtilBoringSSL::bn2str(n_bn, BN_num_bytes(n_bn)).ValueOrDie());
  EXPECT_EQ(key->d,
            SubtleUtilBoringSSL::bn2str(d_bn, BN_num_bytes(d_bn)).ValueOrDie());
  // Verify private key factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(rsa_.get(), &p_bn, &q_bn);
  EXPECT_EQ(key->p,
            SubtleUtilBoringSSL::bn2str(p_bn, BN_num_bytes(p_bn)).ValueOrDie());
  EXPECT_EQ(key->q,
            SubtleUtilBoringSSL::bn2str(q_bn, BN_num_bytes(q_bn)).ValueOrDie());
  // Verify CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(rsa_.get(), &dp_bn, &dq_bn, &crt_bn);
  EXPECT_EQ(
      key->dp,
      SubtleUtilBoringSSL::bn2str(dp_bn, BN_num_bytes(dp_bn)).ValueOrDie());
  EXPECT_EQ(
      key->dq,
      SubtleUtilBoringSSL::bn2str(dq_bn, BN_num_bytes(dq_bn)).ValueOrDie());
  EXPECT_EQ(
      key->crt,
      SubtleUtilBoringSSL::bn2str(crt_bn, BN_num_bytes(crt_bn)).ValueOrDie());
}

TEST_F(PemParserTest, ReadRsaPublicKeyInvalid) {
  Corrupt(&pem_rsa_pub_key_);
  EXPECT_TRUE(
      !PemParser::ParseRsaPrivateKey(
           absl::string_view(pem_rsa_pub_key_.data(), pem_rsa_pub_key_.size()))
           .ok());
}

TEST_F(PemParserTest, ReadRsaPrivateKeyInvalid) {
  Corrupt(&pem_rsa_prv_key_);
  EXPECT_TRUE(
      !PemParser::ParseRsaPrivateKey(
           absl::string_view(pem_rsa_prv_key_.data(), pem_rsa_prv_key_.size()))
           .ok());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
