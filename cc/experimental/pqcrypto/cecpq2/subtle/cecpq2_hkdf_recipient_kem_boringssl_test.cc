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

#include "tink/experimental/pqcrypto/cecpq2/subtle/cecpq2_hkdf_recipient_kem_boringssl.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "openssl/curve25519.h"
#include "openssl/hrss.h"
#include "tink/config/tink_fips.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// CECPQ2 test vector from BoringSSL
const char kHrssKeyGenEntropy[] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324"
    "25262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849"
    "4a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e"
    "6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293"
    "9495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8"
    "b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdd"
    "dedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102"
    "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627"
    "28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c"
    "4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071"
    "72737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293949596"
    "9798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babb"
    "bcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"
    "e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405"
    "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a"
    "2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374"
    "75767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293949596979899"
    "9a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbebfc0"
    "c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5"
    "e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a"
    "0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354"
    "55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70717273747576777879"
    "7a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e"
    "9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3"
    "c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8"
    "e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d"
    "0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132"
    "333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354555657"
    "58595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c"
    "7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1"
    "a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6"
    "c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb"
    "ecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f10"
    "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435"
    "363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a"
    "5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797c7d7e7f8081"
    "82838485868788898a8b8c8d8e8f909192939495969798999a9b";
const char kCecpq2KemBytes[] =
    "5b9cbc8389eb7b6ce907a61d63b6ea1e46f77b65821fb394bc8508d7584f7365e0c077eb7a"
    "487d744e4f6db95c18e95b476c789d9802849ff24543860ec69348d820ff82389e78b42cb3"
    "42e4b3abdfed65240ca5952cbf4c28fcb8e7c6bc76a0f53f297323f16c107c088e163ada17"
    "a30d4644ee6f70f1885135339176eb98c104db97ab88b90487d9b834d338e790052e45e0ac"
    "360c5958b1f5656d281a39d9d28317eeeb6f7d293c79cf48f16d35c28ce86718cc9d9b8d07"
    "7a4e56a8002e6767bbc1da4a7b9fa64a5c40cce4ddf5c044fea5a21cdcf231f4011f69157e"
    "8c54b6470c1d9f1afaf746a3cb342c184565c4f20ef8c7961d295c90d3dfb28e21f915407e"
    "d384521dd9eeede8711cdb48f52082c461fd6d719fd803908efced4dab6eb2e966fdcc3aa3"
    "99533576ea0888baf0b753f34c1a8f7fe41b8bfc993e4ca9d917106460fd8176e637b0e33e"
    "c0f7067e34a5f4b95f66e681c85eb2266b8cadd0940122f6be1a0b34fc33c084a5e0128a08"
    "ae8aaf550c344b2bdda37cc0ede88d98477c81251b9f08269dfc198e39c41a3c4270493757"
    "870f76b1c4be255e1c0657c6883428df603309c5ccf4c433858b48e827b7722244ffe789f9"
    "7199ed6247b0229ea67cafa9982b5c8a423477a3c8131ecf32a770a8adc1665c8faf146dc4"
    "4505cdcb80fa0ea6ca7286d2b7392677f814d0cdddf7dcda258e3c21fdef92ee52f7c3c7e2"
    "2d1c575abad8aa0d09a7b3cca15ddb042182efbac2c854b1bed72a91d8eb7254c17424245a"
    "03f7cdab91d163f1609f2207ad102b971c6fcec029c2b2b81bbd14c8b98066c186fc935f6e"
    "0b7a7b8e428c08d160b9f866247d88582fd252753a8a1cfa1ea11c9146799ae58addc275ed"
    "0db82b4f8f95cace21a47a0d147f2d98f088c36fadb50424914165d3a57efb531cccd0f77c"
    "91080eddd46c73aaa57ad224c93b6fda068adb2ea8e9e13e08eebe966572686ff750e7a718"
    "dac294dae3bcca03d8f77acc44a160a87fdcef80f462c6064eb6ac7717b7b33ef86d8a6183"
    "3afdbb935b1a33f8ee7d9e5cf8c9d53e3d429be50decc90f6f03b04185b9fef9b1b4c3d913"
    "03fa0de7d1b4c8f6b5117a9209217ba9894c19900d96324f77fc7f8ca3392a56e65cd1860a"
    "72f4a31ba530043c15204be42d1af14448fcdac141db71fd920053e470d0baf6ef1772b8ea"
    "6d41164d1f5918bd1fc56b6a6c2ea61a33748bc59f1601777e37e763e1a38c1f71e94fad15"
    "8bf3c9acdc19ad921800f6a1d597a33d9e7802c38f75d8ad22bfef195d15341a7c9bafd4f2"
    "f95f72889ce458da468f79302bd93bbcab2877750e2c23479514ebf04a3e5393a7f4829c34"
    "8b8042b2a7b07c6ce107f4343eed339cb3dea59161258e8c5456be1aac17d27aa412542a51"
    "d00ed1c144500539a7b61445caf85f066b5d5ec7e9276f38e031cff8cc2eb94a101bb4344b"
    "90bbf2e03c797f39590c014c0d2d71f1bdda1a78cf266fb5a90720e68cd0add4ca246cc528"
    "1dfbcce79372996163604c5ca9b61532a4bc1ff663612c26a70e5f1b25ce3f64df6db08fd2"
    "e93b35d0598122f165861510e8a7a16fb4341c79d59e8dc8a5bb8271810034556b9656130e"
    "e739a26fbe542a130313d21d719abe0900e18d59b54402";
const char kCecpq2X25519PrivateKeyHex[] =
    "b79cbf241478d6f5139d517cf1beae62296a9e86d05d9e14fcb52d80d30eaebe";
const char kCorrectSharedSecret[] =
    "4ba608d54c2c2159e7aa8f576df5d4403b9ad8d2718cf76e461da09343948e63";
const char kFailSharedSecret[] =
    "c3d8a7f03b25ce23287dd6e7c49596104732fa855266e4f6a4dc79eaaf2757ad";
const char kSaltHex[] = "0b0b0b0b";
const char kInfoHex[] = "0b0b0b0b0b0b0b0b";

// This test evaluates the creation of a Cecpq2HkdfRecipientKemBoringSslTest
// instance with an unknown curve type. It should fail with an
// absl::StatusCode::kUnimplemented error.
TEST(Cecpq2HkdfRecipientKemBoringSslTest, TestUnknownCurve) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  util::SecretData hrss_private_key_seed =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kHrssKeyGenEntropy));
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::UNKNOWN_CURVE,
      util::SecretDataFromStringView(
          test::HexDecodeOrDie(kCecpq2X25519PrivateKeyHex)),
      std::move(hrss_private_key_seed));

  // The instance creation above should fail with an unimplemented algorithm
  // error given the UNKNOWN_CURVE parameter
  EXPECT_EQ(absl::StatusCode::kUnimplemented,
            status_or_recipient_kem.status().code());
}

// This test evaluates the case where a unsupported curve (NIST_P256) is
// specified. This test should fail with an absl::StatusCode::kUnimplemented
// error.
TEST(Cecpq2HkdfRecipientKemBoringSslTest, TestUnsupportedCurve) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  util::SecretData hrss_private_key_seed =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kHrssKeyGenEntropy));
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::NIST_P256,
      util::SecretDataFromStringView(
          test::HexDecodeOrDie(kCecpq2X25519PrivateKeyHex)),
      std::move(hrss_private_key_seed));

  // The instance creation above should fail with an unimplemented algorithm
  // error given the UNKNOWN_CURVE parameter
  EXPECT_EQ(absl::StatusCode::kUnimplemented,
            status_or_recipient_kem.status().code());
}

// This test checks that an error is triggered if an output key lenth smaller
// than 32 bytes is specified.
TEST(Cecpq2HkdfRecipientKemBoringSslTest, TestNotPostQuantumSecureKeyLength) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Not post-quantum secure output key length
  int out_len = 31;

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  util::SecretData hrss_private_key_seed =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kHrssKeyGenEntropy));
  auto cecpq2_recipient_kem_or = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::CURVE25519,
      util::SecretDataFromStringView(
          test::HexDecodeOrDie(kCecpq2X25519PrivateKeyHex)),
      std::move(hrss_private_key_seed));
  ASSERT_THAT(cecpq2_recipient_kem_or.status(), IsOk());
  auto cecpq2_recipient_kem = std::move(cecpq2_recipient_kem_or).value();

  // Recovering the symmetric key
  auto kem_key_or = cecpq2_recipient_kem->GenerateKey(
      test::HexDecodeOrDie(kCecpq2KemBytes), HashType::SHA256,
      test::HexDecodeOrDie(kSaltHex), test::HexDecodeOrDie(kInfoHex), out_len,
      EcPointFormat::COMPRESSED);
  EXPECT_THAT(kem_key_or.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("not post-quantum secure")));
}

TEST(Cecpq2HkdfRecipientKemBoringSslTest, TestRecipientFlowSuccess) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  int out_len = 32;

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  util::SecretData hrss_private_key_seed =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kHrssKeyGenEntropy));
  auto cecpq2_recipient_kem_or = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::CURVE25519,
      util::SecretDataFromStringView(
          test::HexDecodeOrDie(kCecpq2X25519PrivateKeyHex)),
      std::move(hrss_private_key_seed));
  ASSERT_THAT(cecpq2_recipient_kem_or.status(), IsOk());
  auto cecpq2_recipient_kem = std::move(cecpq2_recipient_kem_or).value();

  // Recovering the symmetric key
  auto kem_key_or = cecpq2_recipient_kem->GenerateKey(
      test::HexDecodeOrDie(kCecpq2KemBytes), HashType::SHA256,
      test::HexDecodeOrDie(kSaltHex), test::HexDecodeOrDie(kInfoHex), out_len,
      EcPointFormat::COMPRESSED);
  ASSERT_THAT(kem_key_or.status(), IsOk());

  // The generated symmetric key should match the expected one
  EXPECT_EQ(kCorrectSharedSecret,
            test::HexEncode(util::SecretDataAsStringView(kem_key_or.value())));
}

TEST(Cecpq2HkdfRecipientKemBoringSslTest, TestRecipientFlowFailure) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  int out_len = 32;
  // The following kem_bytes is not correct. The 50-th position of the HRSS
  // kem_bytes has been modified (its original value xored with 4). This
  // modified HRSS kem_bytes matches the one used in BoringSSL test vector. This
  // change will result in an HRSS decapsulation failure which produces a
  // symmetric key using a deterministic algorithm based on HMAC-SHA256.

  std::string kem_bytes_modified = test::HexDecodeOrDie(kCecpq2KemBytes);
  kem_bytes_modified[X25519_PUBLIC_VALUE_LEN + 50] ^= 0x04;

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  util::SecretData hrss_private_key_seed =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kHrssKeyGenEntropy));
  auto cecpq2_recipient_kem_or = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::CURVE25519,
      util::SecretDataFromStringView(
          test::HexDecodeOrDie(kCecpq2X25519PrivateKeyHex)),
      std::move(hrss_private_key_seed));
  ASSERT_THAT(cecpq2_recipient_kem_or.status(), IsOk());
  auto cecpq2_recipient_kem = std::move(cecpq2_recipient_kem_or).value();

  // Recovering the symmetric key
  auto kem_key_or = cecpq2_recipient_kem->GenerateKey(
      kem_bytes_modified, HashType::SHA256, test::HexDecodeOrDie(kSaltHex),
      test::HexDecodeOrDie(kInfoHex), out_len, EcPointFormat::COMPRESSED);
  ASSERT_THAT(kem_key_or.status(), IsOk());

  // The produced symmetric key should match the one produced by CECPQ2 in case
  // of HRSS decapsulation failure for the altered HRSS kem_bytes
  EXPECT_EQ(kFailSharedSecret,
            test::HexEncode(util::SecretDataAsStringView(kem_key_or.value())));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
