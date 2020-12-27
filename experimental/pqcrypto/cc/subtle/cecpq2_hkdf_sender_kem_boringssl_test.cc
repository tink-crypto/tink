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

#include "pqcrypto/cc/subtle/cecpq2_hkdf_sender_kem_boringssl.h"

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "openssl/curve25519.h"
#include "openssl/hrss.h"
#include "openssl/sha.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "pqcrypto/cc/subtle/cecpq2_hkdf_recipient_kem_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class Cecpq2HkdfSenderKemBoringSslTest : public ::testing::Test {};

struct HrssKeyPair {
  util::SecretUniquePtr<struct HRSS_private_key> hrss_private_key =
      util::MakeSecretUniquePtr<struct HRSS_private_key>();
  struct HRSS_public_key hrss_public_key;
  std::string hrss_public_key_marshaled;
};

struct EccKeyPair {
  std::string pub_x;
  std::string pub_y;
  util::SecretData priv;
};

struct Cecpq2KeyPair {
  struct HrssKeyPair hrss_key_pair;
  struct EccKeyPair x25519_key_pair;
};

// This method performs some basic common setup (HRSS and X25519 key generation,
// and marshaling HRSS public key) needed by the tests.
crypto::tink::util::StatusOr<struct Cecpq2KeyPair> HrssTestCommon(
    EllipticCurveType curve_type) {
  Cecpq2KeyPair cecpq2_key_pair;

  // Generating a X25519 key pair
  cecpq2_key_pair.x25519_key_pair.priv.resize(X25519_PRIVATE_KEY_LEN);
  subtle::ResizeStringUninitialized(&(cecpq2_key_pair.x25519_key_pair.pub_x),
                                    X25519_PUBLIC_VALUE_LEN);
  X25519_keypair(const_cast<uint8_t*>(
                 reinterpret_cast<const uint8_t*>(
                 cecpq2_key_pair.x25519_key_pair.pub_x.data())),
                 cecpq2_key_pair.x25519_key_pair.priv.data());

  // Generating a HRSS key pair
  util::SecretData generate_hrss_key_entropy =
      crypto::tink::subtle::Random::GetRandomKeyBytes(HRSS_GENERATE_KEY_BYTES);

  // struct HRSS_public_key pk_dumb;
  HRSS_generate_key(&cecpq2_key_pair.hrss_key_pair.hrss_public_key,
                    cecpq2_key_pair.hrss_key_pair.hrss_private_key.get(),
                    generate_hrss_key_entropy.data());

  // Marshalling the HRSS public key
  subtle::ResizeStringUninitialized(
      &(cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled),
      HRSS_PUBLIC_KEY_BYTES);
  HRSS_marshal_public_key(
      const_cast<uint8_t*>(
      reinterpret_cast<const uint8_t*>(
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled.data())),
      &(cecpq2_key_pair.hrss_key_pair.hrss_public_key));

  return cecpq2_key_pair;
}

// This test evaluates the creation of a Cecpq2HkdfSenderKemBoringSsl instance
// with an unknown curve type parameter. It should fail with an
// util::error::UNIMPLEMENTED error.
TEST_F(Cecpq2HkdfSenderKemBoringSslTest, TestUnknownCurve) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  auto statur_or_cecpq2_key = HrssTestCommon(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(statur_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(statur_or_cecpq2_key).ValueOrDie();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl specifying an unknown
  // curve
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::UNKNOWN_CURVE, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);

  // The instance creation above should fail with an unimplemented algorithm
  // error given the UNKNOWN_CURVE parameter
  EXPECT_EQ(util::error::UNIMPLEMENTED,
            status_or_sender_kem.status().error_code());
}

// This test evaluates the case where an unsupported curve (NIST_P256) is
// specified. This test should fail with an util::error::UNIMPLEMENTED error.
TEST_F(Cecpq2HkdfSenderKemBoringSslTest, TestUnsupportedCurve) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  auto statur_or_cecpq2_key = HrssTestCommon(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(statur_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(statur_or_cecpq2_key).ValueOrDie();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl specifying an unknown
  // curve
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::NIST_P256, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);

  // This test should fail with an unimplemented algorithm error
  EXPECT_EQ(util::error::UNIMPLEMENTED,
            status_or_sender_kem.status().error_code());
}

// This test evaluates if a Sender can successfully generate a symmetric key.
TEST_F(Cecpq2HkdfSenderKemBoringSslTest, TestGenerateKey) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  auto statur_or_cecpq2_key = HrssTestCommon(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(statur_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(statur_or_cecpq2_key).ValueOrDie();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      EllipticCurveType::CURVE25519, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  ASSERT_TRUE(status_or_sender_kem.ok());
  auto sender_kem = std::move(status_or_sender_kem.ValueOrDie());

  // Generating a symmetric key
  uint32_t key_size_in_bytes = HRSS_KEY_BYTES;
  auto status_or_kem_key =
      sender_kem->GenerateKey(HashType::SHA256, "hkdf_salt", "hkdf_info",
                              key_size_in_bytes, EcPointFormat::COMPRESSED);

  // Asserting that the symmetric key has been successfully generated
  ASSERT_TRUE(status_or_kem_key.ok());
  auto kem_key = std::move(status_or_kem_key.ValueOrDie());
  EXPECT_FALSE(kem_key->get_kem_bytes().empty());
  EXPECT_EQ(kem_key->get_symmetric_key().size(), key_size_in_bytes);
}

// This test evaluates the whole KEM flow: from Sender to Recipient. This test
// should successfully generate an encapsulated shared secret that matches with
// a decapsulated shared secret.
TEST_F(Cecpq2HkdfSenderKemBoringSslTest, TestSenderRecipientFullFlowSuccess) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Declaring auxiliary parameters
  EllipticCurveType curve = EllipticCurveType::CURVE25519;
  HashType hash_type = HashType::SHA256;
  EcPointFormat point_format = EcPointFormat::COMPRESSED;
  std::string salt_hex = "0b0b0b0b";
  std::string info_hex = "0b0b0b0b0b0b0b0b";
  int out_len = 32;

  auto statur_or_cecpq2_key = HrssTestCommon(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(statur_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(statur_or_cecpq2_key).ValueOrDie();

  // Creating an instance of Cecpq2HkdfSenderKemBoringSsl
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      curve, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  ASSERT_TRUE(status_or_sender_kem.ok());
  auto sender_kem = std::move(status_or_sender_kem.ValueOrDie());

  // Generating sender's shared secret
  auto status_or_kem_key = sender_kem->GenerateKey(
      hash_type, test::HexDecodeOrDie(salt_hex), test::HexDecodeOrDie(info_hex),
      out_len, point_format);
  ASSERT_TRUE(status_or_kem_key.ok());
  auto kem_key = std::move(status_or_kem_key.ValueOrDie());

  // Initializing recipient's KEM data structure using recipient's private keys
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      curve, cecpq2_key_pair.x25519_key_pair.priv,
      std::move(cecpq2_key_pair.hrss_key_pair.hrss_private_key));
  ASSERT_TRUE(status_or_recipient_kem.ok());
  auto recipient_kem = std::move(status_or_recipient_kem.ValueOrDie());

  // Generating recipient's shared secret
  auto status_or_shared_secret = recipient_kem->GenerateKey(
      kem_key->get_kem_bytes(), hash_type, test::HexDecodeOrDie(salt_hex),
      test::HexDecodeOrDie(info_hex), out_len, point_format);
  ASSERT_TRUE(status_or_shared_secret.ok());

  // Asserting that both shared secrets match
  EXPECT_EQ(test::HexEncode(
                util::SecretDataAsStringView(kem_key->get_symmetric_key())),
            test::HexEncode(util::SecretDataAsStringView(
                status_or_shared_secret.ValueOrDie())));
}

// Method that generates the shared secret returned by HRSS in case of
// decapsulation failure. This shared secret consists of the HMAC of the
// ciphertext using portion of the HRSS private key as the HMAC key.
void createFailureSharedSecret(uint8_t out_shared_key[HRSS_KEY_BYTES],
                               struct HRSS_private_key* in_priv,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len) {
  // Shifting the private key by 15 positions (as in its marshaled version) then
  // by 1760 positions to reach the expected HMAC key used in BoringSSL:
  uint8_t* priv_hmac_ptr =
      reinterpret_cast<uint8_t*>(in_priv->opaque) + 15 + 1760;

  // This is HMAC, expanded inline rather than using the |HMAC| function so that
  // we can avoid dealing with possible allocation failures and so keep this
  // function infallible.
  uint8_t masked_key[SHA256_CBLOCK];
  for (size_t i = 0; i < 32; i++) {
    masked_key[i] = priv_hmac_ptr[i] ^ 0x36;
  }
  std::memset(masked_key + 32, 0x36, 32);

  SHA256_CTX hash_ctx;
  SHA256_Init(&hash_ctx);
  SHA256_Update(&hash_ctx, masked_key, SHA256_CBLOCK);
  SHA256_Update(&hash_ctx, ciphertext, ciphertext_len);
  uint8_t inner_digest[SHA256_DIGEST_LENGTH];
  SHA256_Final(inner_digest, &hash_ctx);

  for (size_t i = 0; i < 32; i++) {
    masked_key[i] ^= (0x5c ^ 0x36);
  }
  memset(masked_key + 32, 0x5c, 32);

  SHA256_Init(&hash_ctx);
  SHA256_Update(&hash_ctx, masked_key, sizeof(masked_key));
  SHA256_Update(&hash_ctx, inner_digest, sizeof(inner_digest));
  OPENSSL_STATIC_ASSERT(HRSS_KEY_BYTES == SHA256_DIGEST_LENGTH,
                        "HRSS shared key length incorrect");
  SHA256_Final(out_shared_key, &hash_ctx);
}

// This test evaluates the whole KEM flow: from Sender to Recipient. This test
// is essentially the same as TestSenderRecipientFullFlowSuccess with the
// difference that we alter bytes of the kem_bytes thus preventing the two
// shared secrets to match.
TEST_F(Cecpq2HkdfSenderKemBoringSslTest,
       DISABLED_TestSenderRecipientFullFlowFailure) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Declaring auxiliary parameters
  EllipticCurveType curve = EllipticCurveType::CURVE25519;
  HashType hash_type = HashType::SHA256;
  EcPointFormat point_format = EcPointFormat::COMPRESSED;
  std::string info_hex = "0b0b0b0b0b0b0b0b";
  std::string salt_hex = "0b0b0b0b";
  int out_len = 32;

  auto statur_or_cecpq2_key = HrssTestCommon(EllipticCurveType::CURVE25519);
  ASSERT_TRUE(statur_or_cecpq2_key.ok());
  auto cecpq2_key_pair = std::move(statur_or_cecpq2_key).ValueOrDie();

  // Initializing sender's KEM data structure using recipient's public keys
  auto status_or_sender_kem = Cecpq2HkdfSenderKemBoringSsl::New(
      curve, cecpq2_key_pair.x25519_key_pair.pub_x,
      cecpq2_key_pair.x25519_key_pair.pub_y,
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  ASSERT_TRUE(status_or_sender_kem.ok());
  auto sender_kem = std::move(status_or_sender_kem.ValueOrDie());

  // storing an HRSS private key backup needed for the defective testing flow:
  struct HRSS_private_key recipient_hrss_priv_copy;
  std::memcpy(recipient_hrss_priv_copy.opaque,
              cecpq2_key_pair.hrss_key_pair.hrss_private_key->opaque,
              sizeof(recipient_hrss_priv_copy.opaque));

  // Generating sender's shared secret (using salt_hex1)
  auto status_or_kem_key = sender_kem->GenerateKey(
      hash_type, test::HexDecodeOrDie(salt_hex), test::HexDecodeOrDie(info_hex),
      out_len, point_format);
  ASSERT_TRUE(status_or_kem_key.ok());
  auto kem_key = std::move(status_or_kem_key.ValueOrDie());

  // Initializing recipient's KEM data structure using recipient's private keys
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      curve, cecpq2_key_pair.x25519_key_pair.priv,
      std::move(cecpq2_key_pair.hrss_key_pair.hrss_private_key));
  ASSERT_TRUE(status_or_recipient_kem.ok());
  auto recipient_kem = std::move(status_or_recipient_kem.ValueOrDie());

  // Here, we corrupt kem_bytes (we change all bytes to "a") so that
  // the HRSS shared secret is not successfully recovered
  std::string kem_bytes = kem_key->get_kem_bytes();
  for (int i = 0; i < HRSS_CIPHERTEXT_BYTES; i++)
    kem_bytes[X25519_PUBLIC_VALUE_LEN + i] = 'a';

  // Generating the defective recipient's shared secret
  auto status_or_shared_secret = recipient_kem->GenerateKey(
      kem_bytes, hash_type, test::HexDecodeOrDie(salt_hex),
      test::HexDecodeOrDie(info_hex), out_len, point_format);

  // Recover the X25519 shared secret (needed for the defective shared secret
  // computation)
  util::SecretData x25519_shared_secret(X25519_SHARED_KEY_LEN);
  X25519(x25519_shared_secret.data(),
         cecpq2_key_pair.x25519_key_pair.priv.data(),
         reinterpret_cast<const uint8_t*>(kem_bytes.data()));

  // Computing the shared secret returned by BoringSSL's HRSS assuming that HRSS
  // decapsulation fails
  util::SecretData hrss_out_shared_key_defective(HRSS_KEY_BYTES);
  createFailureSharedSecret(hrss_out_shared_key_defective.data(),
                            &recipient_hrss_priv_copy,
                            reinterpret_cast<const uint8_t*>(
                                kem_bytes.data() + X25519_PUBLIC_VALUE_LEN),
                            HRSS_CIPHERTEXT_BYTES);

  // Concatenate both shared secrets (correct X25519 and wrong HRSS) and
  // kem_bytes
  std::string kem_bytes_and_shared_secrets = absl::StrCat(
      kem_bytes, util::SecretDataAsStringView(x25519_shared_secret),
      util::SecretDataAsStringView(hrss_out_shared_key_defective));
  util::SecretData ikm =
      util::SecretDataFromStringView(kem_bytes_and_shared_secrets);

  // Compute symmetric key from both shared secrets, kem_bytes, hkdf_salt and
  // hkdf_info using HKDF
  auto symmetric_key_or =
      Hkdf::ComputeHkdf(hash_type, ikm, test::HexDecodeOrDie(salt_hex),
                        test::HexDecodeOrDie(info_hex), out_len);
  ASSERT_TRUE(symmetric_key_or.ok());
  util::SecretData symmetric_key = symmetric_key_or.ValueOrDie();

  // Asserting that the generated shared secret matches with the one that should
  // be produced by HRSS in case of HRSS decapsulation failure:
  EXPECT_EQ(test::HexEncode(util::SecretDataAsStringView(symmetric_key)),
            test::HexEncode(util::SecretDataAsStringView(
                status_or_shared_secret.ValueOrDie())));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
