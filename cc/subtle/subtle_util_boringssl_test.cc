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

#include "cc/subtle/subtle_util_boringssl.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "cc/util/test_util.h"
#include "gtest/gtest.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/x509.h"

namespace cloud {
namespace crypto {
namespace tink {
namespace {

class SubtleUtilBoringSSLTest : public ::testing::Test {};
struct EncodingTestVector {
  EcPointFormat format;
  std::string x_hex;
  std::string y_hex;
  std::string encoded_hex;
  EllipticCurveType curve;
};

static const std::vector<EncodingTestVector> encoding_test_vector(
    {{EcPointFormat::UNCOMPRESSED,
      "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec66"
      "19b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
      "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327ac"
      "aac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
      "0400093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec"
      "6619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a"
      "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327ac"
      "aac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
      EllipticCurveType::NIST_P521},
     {EcPointFormat::COMPRESSED,
      "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec66"
      "19b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
      "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327ac"
      "aac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
      "0300093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec"
      "6619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
      EllipticCurveType::NIST_P521}});

TEST_F(SubtleUtilBoringSSLTest, testEcPointEncode) {
  for (const EncodingTestVector& test : encoding_test_vector) {
    std::string x_str = test::HexDecodeOrDie(test.x_hex);
    std::string y_str = test::HexDecodeOrDie(test.y_hex);
    bssl::UniquePtr<BIGNUM> x(
        BN_bin2bn(reinterpret_cast<const unsigned char*>(x_str.data()),
                  x_str.length(), nullptr));
    bssl::UniquePtr<BIGNUM> y(
        BN_bin2bn(reinterpret_cast<const unsigned char*>(y_str.data()),
                  y_str.length(), nullptr));
    auto status_or_group = SubtleUtilBoringSSL::GetEcGroup(test.curve);
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(status_or_group.ValueOrDie()));
    EXPECT_TRUE(1 == EC_POINT_set_affine_coordinates_GFp(
                         status_or_group.ValueOrDie(), point.get(), x.get(),
                         y.get(), nullptr));
    auto status_or_string = SubtleUtilBoringSSL::EcPointEncode(
        test.curve, test.format, point.get());
    EXPECT_TRUE(status_or_string.ok());
    EXPECT_EQ(test.encoded_hex, test::HexEncode(status_or_string.ValueOrDie()));
  }
}

TEST_F(SubtleUtilBoringSSLTest, testEcPointDecode) {
  for (const EncodingTestVector& test : encoding_test_vector) {
    std::string x_str = test::HexDecodeOrDie(test.x_hex);
    std::string y_str = test::HexDecodeOrDie(test.y_hex);
    std::string encoded_str = test::HexDecodeOrDie(test.encoded_hex);
    bssl::UniquePtr<BIGNUM> x(
        BN_bin2bn(reinterpret_cast<const unsigned char*>(x_str.data()),
                  x_str.length(), nullptr));
    bssl::UniquePtr<BIGNUM> y(
        BN_bin2bn(reinterpret_cast<const unsigned char*>(y_str.data()),
                  y_str.length(), nullptr));
    auto status_or_group = SubtleUtilBoringSSL::GetEcGroup(test.curve);
    bssl::UniquePtr<EC_POINT> point(EC_POINT_new(status_or_group.ValueOrDie()));
    EXPECT_TRUE(1 == EC_POINT_set_affine_coordinates_GFp(
                         status_or_group.ValueOrDie(), point.get(), x.get(),
                         y.get(), nullptr));
    auto status_or_ec_point = SubtleUtilBoringSSL::EcPointDecode(
        test.curve, test.format, encoded_str);
    EXPECT_TRUE(status_or_ec_point.ok());
    EXPECT_EQ(0, EC_POINT_cmp(status_or_group.ValueOrDie(), point.get(),
                              status_or_ec_point.ValueOrDie(), nullptr));
    // Modify the 1st byte.
    encoded_str = std::string("0") + encoded_str.substr(1);
    status_or_ec_point = SubtleUtilBoringSSL::EcPointDecode(
        test.curve, test.format, encoded_str);
    EXPECT_FALSE(status_or_ec_point.ok());
    EXPECT_LE(0, status_or_ec_point.status().error_message().find(
                     "point should start with"));
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
