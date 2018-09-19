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

#include <iostream>

#include "tink/subtle/ecies_hkdf_sender_kem_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecies_hkdf_recipient_kem_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

// TODO(quannguyen): Add extensive tests.
// It's important to test compatibility with Java.
namespace crypto {
namespace tink {
namespace subtle {
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

TEST_F(EciesHkdfSenderKemBoringSslTest, testSenderRecipientBasic) {
  for (const TestVector& test : test_vector) {
    auto test_key = SubtleUtilBoringSSL::GetNewEcKey(test.curve).ValueOrDie();
    auto status_or_sender_kem = EciesHkdfSenderKemBoringSsl::New(
        test.curve, test_key.pub_x, test_key.pub_y);
    ASSERT_TRUE(status_or_sender_kem.ok());
    auto sender_kem = std::move(status_or_sender_kem.ValueOrDie());
    auto status_or_kem_key = sender_kem->GenerateKey(
        test.hash, test::HexDecodeOrDie(test.salt_hex),
        test::HexDecodeOrDie(test.info_hex), test.out_len, test.point_format);
    ASSERT_TRUE(status_or_kem_key.ok());
    auto kem_key = std::move(status_or_kem_key.ValueOrDie());
    auto ecies_recipient(std::move(EciesHkdfRecipientKemBoringSsl::New(
        test.curve, test_key.priv).ValueOrDie()));
    auto status_or_shared_secret = ecies_recipient->GenerateKey(
        kem_key->get_kem_bytes(), test.hash,
        test::HexDecodeOrDie(test.salt_hex),
        test::HexDecodeOrDie(test.info_hex),
        test.out_len, test.point_format);
    std::cout << test::HexEncode(kem_key->get_kem_bytes()) << std::endl;
    EXPECT_EQ(test::HexEncode(kem_key->get_symmetric_key()),
              test::HexEncode(status_or_shared_secret.ValueOrDie()));
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
