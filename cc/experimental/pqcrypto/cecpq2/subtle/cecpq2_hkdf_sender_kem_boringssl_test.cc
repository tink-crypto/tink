// Copyright 2020 Google LLC
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

#include "experimental/pqcrypto/cecpq2/subtle/cecpq2_hkdf_sender_kem_boringssl.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "openssl/curve25519.h"
#include "openssl/hrss.h"
#include "openssl/sha.h"
#include "tink/config/tink_fips.h"
#include "experimental/pqcrypto/cecpq2/subtle/cecpq2_hkdf_recipient_kem_boringssl.h"
#include "experimental/pqcrypto/cecpq2/subtle/cecpq2_subtle_boringssl_util.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// This test evaluates the creation of a Cecpq2HkdfSenderKemBoringSsl instance
// with an unknown curve type parameter. It should fail with an
// absl::StatusCode::kUnimplemented error.
TEST(Cecpq2HkdfSenderKemBoringSslTest, TestUnknownCurve) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  auto status_or_cecpq2_key =
      pqc::GenerateCecpq2Keypair(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(status_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(status_or_cecpq2_key).value();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl specifying an unknown
  // curve
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::UNKNOWN_CURVE, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);

  // The instance creation above should fail with an unimplemented algorithm
  // error given the UNKNOWN_CURVE parameter
  EXPECT_EQ(absl::StatusCode::kUnimplemented,
            status_or_sender_kem.status().code());
}

// This test evaluates the case where an unsupported curve (NIST_P256) is
// specified. This test should fail with an absl::StatusCode::kUnimplemented
// error.
TEST(Cecpq2HkdfSenderKemBoringSslTest, TestUnsupportedCurve) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  auto status_or_cecpq2_key =
      pqc::GenerateCecpq2Keypair(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(status_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(status_or_cecpq2_key).value();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl specifying a
  // unsupported curve
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::NIST_P256, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);

  // This test should fail with an unimplemented algorithm error
  EXPECT_EQ(absl::StatusCode::kUnimplemented,
            status_or_sender_kem.status().code());
}

// This test checks that an error is triggered if an output key lenth smaller
// than 32 bytes is specified.
TEST(Cecpq2HkdfSenderKemBoringSslTest, TestNotPostQuantumSecureKeyLength) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Declaring auxiliary parameters
  std::string salt_hex = "0b0b0b0b";
  std::string info_hex = "0b0b0b0b0b0b0b0b";

  // Not post-quantum secure output key length
  int out_len = 31;

  auto status_or_cecpq2_key =
      pqc::GenerateCecpq2Keypair(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(status_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(status_or_cecpq2_key).value();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  ASSERT_THAT(status_or_sender_kem.status(), IsOk());
  auto sender_kem = std::move(status_or_sender_kem.value());

  // Generating a symmetric key
  auto status_or_kem_key = sender_kem->GenerateKey(
      HashType::SHA256, test::HexDecodeOrDie(salt_hex),
      test::HexDecodeOrDie(info_hex), out_len, EcPointFormat::COMPRESSED);

  EXPECT_THAT(status_or_kem_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("not post-quantum secure")));
}

// This test evaluates if a Sender can successfully generate a symmetric key.
TEST(Cecpq2HkdfSenderKemBoringSslTest, TestGenerateKey) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Declaring auxiliary parameters
  std::string salt_hex = "0b0b0b0b";
  std::string info_hex = "0b0b0b0b0b0b0b0b";
  int out_len = 32;

  auto status_or_cecpq2_key =
      pqc::GenerateCecpq2Keypair(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(status_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(status_or_cecpq2_key).value();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  ASSERT_THAT(status_or_sender_kem.status(), IsOk());
  auto sender_kem = std::move(status_or_sender_kem.value());

  // Generating a symmetric key
  auto status_or_kem_key = sender_kem->GenerateKey(
      HashType::SHA256, test::HexDecodeOrDie(salt_hex),
      test::HexDecodeOrDie(info_hex), out_len, EcPointFormat::COMPRESSED);

  // Asserting that the symmetric key has been successfully generated
  ASSERT_THAT(status_or_kem_key.status(), IsOk());
  auto kem_key = std::move(status_or_kem_key.value());
  EXPECT_FALSE(kem_key->get_kem_bytes().empty());
  EXPECT_EQ(kem_key->get_symmetric_key().size(), out_len);
}

// This test evaluates the whole KEM flow: from Sender to Recipient. This test
// should successfully generate an encapsulated shared secret that matches with
// a decapsulated shared secret.
TEST(Cecpq2HkdfSenderKemBoringSslTest, TestSenderRecipientFullFlowSuccess) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Declaring auxiliary parameters
  std::string salt_hex = "0b0b0b0b";
  std::string info_hex = "0b0b0b0b0b0b0b0b";
  int out_len = 32;

  auto status_or_cecpq2_key =
      pqc::GenerateCecpq2Keypair(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(status_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(status_or_cecpq2_key).value();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  ASSERT_TRUE(status_or_sender_kem.ok());
  auto sender_kem = std::move(status_or_sender_kem.value());

  // Generating sender's shared secret
  auto status_or_kem_key = sender_kem->GenerateKey(
      HashType::SHA256, test::HexDecodeOrDie(salt_hex),
      test::HexDecodeOrDie(info_hex), out_len, EcPointFormat::COMPRESSED);
  ASSERT_TRUE(status_or_kem_key.ok());
  auto kem_key = std::move(status_or_kem_key.value());

  // Initializing recipient's KEM data structure using recipient's private keys
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.priv,
      std::move(cecpq2_key_pair.hrss_key_pair.hrss_private_key_seed));
  ASSERT_TRUE(status_or_recipient_kem.ok());
  auto recipient_kem = std::move(status_or_recipient_kem.value());

  // Generating recipient's shared secret
  auto status_or_shared_secret = recipient_kem->GenerateKey(
      kem_key->get_kem_bytes(), HashType::SHA256,
      test::HexDecodeOrDie(salt_hex), test::HexDecodeOrDie(info_hex), out_len,
      EcPointFormat::COMPRESSED);
  ASSERT_TRUE(status_or_shared_secret.ok());

  // Asserting that both shared secrets match
  EXPECT_EQ(test::HexEncode(
                util::SecretDataAsStringView(kem_key->get_symmetric_key())),
            test::HexEncode(
                util::SecretDataAsStringView(status_or_shared_secret.value())));
}

// This test evaluates the whole KEM flow as in
// TestSenderRecipientFullFlowSuccess with the difference that the caller's
// public key is erased after Cecpq2HkdfSenderKemBoringSsl object is created.
// This test would detect if the caller's public key buffers are being used
// by Cecpq2HkdfSenderKemBoringSsl instead of Cecpq2HkdfSenderKemBoringSsl
// having its own explicit copy.
TEST(Cecpq2HkdfSenderKemBoringSslTest, TestFullFlowErasedCallersPublicKey) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Declaring auxiliary parameters
  std::string salt_hex = "0b0b0b0b";
  std::string info_hex = "0b0b0b0b0b0b0b0b";
  int out_len = 32;

  auto status_or_cecpq2_key =
      pqc::GenerateCecpq2Keypair(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(status_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(status_or_cecpq2_key).value();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  ASSERT_THAT(status_or_sender_kem.status(), IsOk());
  auto sender_kem = std::move(status_or_sender_kem.value());

  // Erasing caller's public key buffers
  cecpq2_key_pair.x25519_key_pair.pub_x.clear();
  cecpq2_key_pair.x25519_key_pair.pub_y.clear();
  cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled.clear();

  // Generating sender's shared secret
  auto status_or_kem_key = sender_kem->GenerateKey(
      HashType::SHA256, test::HexDecodeOrDie(salt_hex),
      test::HexDecodeOrDie(info_hex), out_len, EcPointFormat::COMPRESSED);
  ASSERT_THAT(status_or_kem_key.status(), IsOk());
  auto kem_key = std::move(status_or_kem_key.value());

  // Initializing recipient's KEM data structure using recipient's private keys
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.priv,
      std::move(cecpq2_key_pair.hrss_key_pair.hrss_private_key_seed));
  ASSERT_THAT(status_or_recipient_kem.status(), IsOk());
  auto recipient_kem = std::move(status_or_recipient_kem.value());

  // Generating recipient's shared secret
  auto status_or_shared_secret = recipient_kem->GenerateKey(
      kem_key->get_kem_bytes(), HashType::SHA256,
      test::HexDecodeOrDie(salt_hex), test::HexDecodeOrDie(info_hex), out_len,
      EcPointFormat::COMPRESSED);
  ASSERT_THAT(status_or_shared_secret.status(), IsOk());

  // Asserting that both shared secrets match
  EXPECT_EQ(test::HexEncode(
                util::SecretDataAsStringView(kem_key->get_symmetric_key())),
            test::HexEncode(
                util::SecretDataAsStringView(status_or_shared_secret.value())));
}

// This test evaluates the whole KEM flow: from Sender to Recipient. This test
// is essentially the same as TestSenderRecipientFullFlowSuccess with the
// difference that we alter bytes of the kem_bytes thus preventing the two
// shared secrets to match.
TEST(Cecpq2HkdfSenderKemBoringSslTest, TestSenderRecipientFullFlowFailure) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Declaring auxiliary parameters
  std::string info_hex = "0b0b0b0b0b0b0b0b";
  std::string salt_hex = "0b0b0b0b";
  int out_len = 32;

  auto status_or_cecpq2_key =
      pqc::GenerateCecpq2Keypair(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(status_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(status_or_cecpq2_key).value();

  // Initializing sender's KEM data structure using recipient's public keys
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  ASSERT_THAT(status_or_sender_kem.status(), IsOk());
  auto sender_kem = std::move(status_or_sender_kem.value());

  // Generating sender's shared secret (using salt_hex1)
  auto status_or_kem_key = sender_kem->GenerateKey(
      HashType::SHA256, test::HexDecodeOrDie(salt_hex),
      test::HexDecodeOrDie(info_hex), out_len, EcPointFormat::COMPRESSED);
  ASSERT_THAT(status_or_kem_key.status(), IsOk());
  auto kem_key = std::move(status_or_kem_key.value());

  // Initializing recipient's KEM data structure using recipient's private keys
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.priv,
      std::move(cecpq2_key_pair.hrss_key_pair.hrss_private_key_seed));
  ASSERT_THAT(status_or_recipient_kem.status(), IsOk());
  auto recipient_kem = std::move(status_or_recipient_kem.value());

  // Here, we corrupt kem_bytes (we change all bytes to "a") so that
  // the HRSS shared secret is not successfully recovered
  std::string kem_bytes = kem_key->get_kem_bytes();
  for (int i = 0; i < HRSS_CIPHERTEXT_BYTES; i++)
    kem_bytes[X25519_PUBLIC_VALUE_LEN + i] = 'a';

  // Generating the defective recipient's shared secret
  auto status_or_shared_secret = recipient_kem->GenerateKey(
      kem_bytes, HashType::SHA256, test::HexDecodeOrDie(salt_hex),
      test::HexDecodeOrDie(info_hex), out_len, EcPointFormat::COMPRESSED);

  // With very high probability, the shared secrets should not match
  EXPECT_NE(test::HexEncode(
                util::SecretDataAsStringView(kem_key->get_symmetric_key())),
            test::HexEncode(
                util::SecretDataAsStringView(status_or_shared_secret.value())));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
