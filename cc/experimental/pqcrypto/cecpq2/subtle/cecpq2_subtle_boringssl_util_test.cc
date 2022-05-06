// Copyright 2017 Google Inc.
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

#include "tink/experimental/pqcrypto/cecpq2/subtle/cecpq2_subtle_boringssl_util.h"

#include <string>

#include "openssl/hrss.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace pqc {

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

const char kExpectedPub[] =
    "4a21397cb4a658153577e42a0279c002e221275f49c72c14b6e067c2c709620ce5239c40d7"
    "7ef5555aa2d09fd38c677b48a4538d39b1cc9929f783bf6f9b167323ccc38698b17c53b1f5"
    "f4ddc8975ed36d63cef3a2f6ef94ed4a3ee64ba2fb87a3bc651c176425a7b4a1e68406720c"
    "28e8fcaacaf8207989a9f060dfd6d4e0af995421af76d59a3180ea7f036c1474069c93e393"
    "cc464d82dadf67e96d582b49f31071a0c5eca029d77c43d5057e148c3928f9463dc1106c2f"
    "aaca11876ae2b1f63176b0dc308a977ddce4d118e90391f5d2944d71f735c83e46afa3eb35"
    "070177c558ca82673e4f0188a4a0ea0ab71306beb661a4a228e232cf2546cfcef5579b748f"
    "fdbcfa3aa21822f1b14312e8e2e306e61ca7762d0de55fbd8fa095cde928dbcce56633d44b"
    "f90c429b27ee11d0e30b9dce2c917a0eb8de3173868e3459932e379dc23e890b47ffa65521"
    "e64f727ccce5b8182c10cbce48a5c526b61976c538f03872ec22f925de1c0c1b3e43c55c8c"
    "dbf14266bcdfa0824bece15042578460fd89121bf6f94d0d16e8a4e2672c8f22eaba4634ce"
    "978b4c380e1682b6f334380787732a3d80564b8567ca2a19b6b62cfed802e5add0617973ab"
    "da3ba451b3f78599b2d06497b73c0e58dfd29898181af559cdc54817109fd819bdd042711c"
    "30c676e9b0eef53805be9b6c0db0d0da1c89bd405dc25abe83a6b547a7f8b9bfa265171ed8"
    "2842beb035f67b8838bef5b51b637a83920d64ad925997555c60ab488e232722753b7c9c69"
    "13526baefd38e54b36785592b58f25de0e93e31d8362056a5aff7f77f71bfc2145f7b8facb"
    "005e85f92f152fcf179e84f6f5156eddb47344c22c74ae275f19e75161c182cef15ba06f0b"
    "131068b7eefb8a85e2d6175526a5c5b39445df49e650f899d83ccb9480673b73acf6463163"
    "b31b47ce403f8cd082c4793a7c4810e39798dc0b6242fa2605f68c32a9b62c4f85d29bf389"
    "1f91ca123de2a80bca64280ea7fdd8a3cb0ad9972dc3f23974dbe39a871ae033e392e8deb5"
    "0828cbd7b679ec71cce5d14b89965ffafd4bd0a8660db4a75156bca774077fae0ef69c13d9"
    "f2ed12a9873eb79d538a822d032fac948495002909013862ffaffd102b3103b24f51fb7627"
    "1e2582796569fa24afcbe8408d7dd29a12692fe4ce99984f6c46fd634050ef2202682e53bb"
    "00a365613e97d45fa2c166cd04dcda5510280d4011e668ed68387d20c3979dcb6e30fcbe63"
    "e7724705f50b7e663bc53a855aa3c5729db9c1b480986e4086c9cba3ab77c256fccb6e12f5"
    "6362f8ff9115a7a15eb6ee694d5b5f4efad361caec14fdd910f54a055f29cb772c2de29067"
    "627875a94e20000c9184baed1ccebd574fa52f596c4cdf5faa32f086091536c6e66a24b4b3"
    "09dd32c595ac60b5099736a13c8f0e908ecdd04975f7f38080cb1feef26a2f198cba1000da"
    "13ef102bb7effdd1e07cf84601699b9980511f743b6793185ed4346c817602ef91a4222a23"
    "1b584375651387986014252867a3348ce0d5d3513368ff65595aa7b26b01ad70067301511b"
    "e1ec282f8a855a10d00e6b35452e61dd7720b1353ba8dd8ae2157907";

TEST(CreatesNewCecpq2KeyPairTest, GeneratesDifferentKeysEveryTime) {
  // Generating two HRSS key pairs
  crypto::tink::util::SecretData hrss_key_entropy1 =
      crypto::tink::subtle::Random::GetRandomKeyBytes(HRSS_GENERATE_KEY_BYTES);
  auto keypair1 = crypto::tink::pqc::GenerateHrssKeyPair(hrss_key_entropy1);
  crypto::tink::util::SecretData hrss_key_entropy2 =
      crypto::tink::subtle::Random::GetRandomKeyBytes(HRSS_GENERATE_KEY_BYTES);
  auto keypair2 = crypto::tink::pqc::GenerateHrssKeyPair(hrss_key_entropy2);

  std::string keypair1_pub_marsh_str(
      reinterpret_cast<const char*>(
          keypair1.value().hrss_public_key_marshaled.data()),
      HRSS_PUBLIC_KEY_BYTES);
  std::string keypair2_pub_marsh_str(
      reinterpret_cast<const char*>(
          keypair2.value().hrss_public_key_marshaled.data()),
      HRSS_PUBLIC_KEY_BYTES);

  // the two HRSS key pairs should be different with very high probability
  EXPECT_NE(keypair1_pub_marsh_str, keypair2_pub_marsh_str);
}

TEST(CreatesNewCecpq2KeyPairTest, SuccessfullHrssKeyGen) {
  // Generating HRSS key pair from BoringSSL test vector
  std::string hrss_key_gen_entropy_str(
      reinterpret_cast<const char*>(
          test::HexDecodeOrDie(kHrssKeyGenEntropy).data()),
      HRSS_GENERATE_KEY_BYTES);
  util::SecretData hrss_key_gen_entropy =
      util::SecretDataFromStringView(hrss_key_gen_entropy_str);
  auto keypair = crypto::tink::pqc::GenerateHrssKeyPair(hrss_key_gen_entropy);

  // Checking that the generated HRSS public key matched the test vector one
  EXPECT_EQ(test::HexEncode(keypair.value().hrss_public_key_marshaled),
            kExpectedPub);
}

}  // namespace pqc
}  // namespace tink
}  // namespace crypto
