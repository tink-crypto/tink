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

#include "tink/subtle/ecies_hkdf_recipient_kem_boringssl.h"

#include "tink/subtle/common_enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class EciesHkdfRecipientKemBoringSslTest : public ::testing::Test {};

struct TestVector {
  EllipticCurveType curve;
  HashType hash;
  EcPointFormat point_format;
  std::string pub_encoded_hex;
  std::string priv_hex;
  std::string salt_hex;
  std::string info_hex;
  int out_len;
  std::string out_key_hex;
};

static const std::vector<TestVector> test_vector(
    {{EllipticCurveType::NIST_P256, HashType::SHA256,
      EcPointFormat::UNCOMPRESSED,
      "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"
      "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
      "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
      "0b0b0b0b", "0b0b0b0b0b0b0b0b", 32,
      "0f19c0f322fc0a4b73b32bac6a66baa274de261db38a57f11ee4896ede24dbba"}});

TEST_F(EciesHkdfRecipientKemBoringSslTest, testBasic) {
  for (const TestVector& test : test_vector) {
    auto ecies_kem(std::move(EciesHkdfRecipientKemBoringSsl::New(
        test.curve, test::HexDecodeOrDie(test.priv_hex)).ValueOrDie()));
    auto status_or_string =
        ecies_kem->EciesHkdfRecipientKemBoringSsl::GenerateKey(
            test::HexDecodeOrDie(test.pub_encoded_hex), test.hash,
            test::HexDecodeOrDie(test.salt_hex),
            test::HexDecodeOrDie(test.info_hex), test.out_len,
            test.point_format);
    EXPECT_TRUE(status_or_string.ok());

    EXPECT_EQ(test.out_key_hex, test::HexEncode(status_or_string.ValueOrDie()));
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
