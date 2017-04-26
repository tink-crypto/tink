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

#include "cc/subtle/ecies_hkdf_sender_kem_boringssl.h"
#include "cc/subtle/ecies_hkdf_recipient_kem_boringssl.h"
#include "cc/subtle/subtle_util_boringssl.h"
#include "cc/util/test_util.h"
#include "gtest/gtest.h"
#include "openssl/bn.h"
// TODO(quannguyen): Add extensive tests.
// It's important to test compatability with Java.
namespace cloud {
namespace crypto {
namespace tink {
namespace {

class EciesHkdfSenderKemBoringSslTest : public ::testing::Test {};

struct TestVector {
  EllipticCurveType curve;
  HashType hash;
  EcPointFormat point_format;
  std::string salt_hex;
  std::string info_hex;
  int out_len;
};

static const std::vector<TestVector> test_vector(
    {{
         EllipticCurveType::NIST_P256, HashType::SHA256,
         EcPointFormat::UNCOMPRESSED, "0b0b0b0b", "0b0b0b0b0b0b0b0b", 32,
     },
     {
         EllipticCurveType::NIST_P256, HashType::SHA256,
         EcPointFormat::COMPRESSED, "0b0b0b0b", "0b0b0b0b0b0b0b0b", 32,
     }});

std::string bn2str(const BIGNUM* bn) {
  size_t bn_size_in_bytes = BN_num_bytes(bn);
  std::unique_ptr<uint8_t> res(new uint8_t[bn_size_in_bytes]);
  BN_bn2bin(bn, &res.get()[0]);
  return std::string(reinterpret_cast<const char*>(res.get()),
                     bn_size_in_bytes);
}

TEST_F(EciesHkdfSenderKemBoringSslTest, testSenderRecipientBasic) {
  for (const TestVector& test : test_vector) {
    auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(test.curve);
    bssl::UniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
    bssl::UniquePtr<EC_KEY> key1(EC_KEY_new());
    EC_KEY_set_group(key1.get(), group.get());
    EC_KEY_generate_key(key1.get());
    const BIGNUM* priv1 = EC_KEY_get0_private_key(key1.get());
    const EC_POINT* pub1 = EC_KEY_get0_public_key(key1.get());
    bssl::UniquePtr<BIGNUM> pub1x_bn(BN_new());
    bssl::UniquePtr<BIGNUM> pub1y_bn(BN_new());
    EC_POINT_get_affine_coordinates_GFp(group.get(), pub1, pub1x_bn.get(),
                                        pub1y_bn.get(), nullptr);
    std::string pub1x_str = bn2str(pub1x_bn.get());
    std::string pub1y_str = bn2str(pub1y_bn.get());
    EciesHkdfSenderKemBoringSsl ecies_sender(test.curve, pub1x_str, pub1y_str);
    auto status_or_kem_key = ecies_sender.GenerateKey(
        test.hash, test::HexDecodeOrDie(test.salt_hex),
        test::HexDecodeOrDie(test.info_hex), test.out_len, test.point_format);
    EciesHkdfSenderKemBoringSsl::KemKey kem_key =
        status_or_kem_key.ValueOrDie();
    std::string priv1_str = bn2str(priv1);
    EciesHkdfRecipientKemBoringSsl ecies_recipient(test.curve, priv1_str);
    auto status_or_shared_secret = ecies_recipient.GenerateKey(
        kem_key.get_kem_bytes(), test.hash, test::HexDecodeOrDie(test.salt_hex),
        test::HexDecodeOrDie(test.info_hex), test.out_len, test.point_format);
    std::cout << test::HexEncode(kem_key.get_kem_bytes()) << std::endl;
    EXPECT_EQ(test::HexEncode(kem_key.get_symmetric_key()),
              test::HexEncode(status_or_shared_secret.ValueOrDie()));
  }
}
}  // namespace
}  // namespace tink
}  // namespace crypto
}  // namespace cloud

int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
