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

#include "cc/subtle/ec_util.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "cc/util/test_util.h"
#include "gtest/gtest.h"

using google::crypto::tink::EllipticCurveType;

namespace crypto {
namespace tink {
namespace {

// TODO(quannguyen): Add extensive tests.
class EcUtilTest : public ::testing::Test {};

// Test vectors from
// http://csrc.nist.gov/groups/STM/cavp/component-testing.html#ecc-cdh.
struct TestVector {
  std::string pubx_hex;
  std::string puby_hex;
  std::string priv_hex;
  std::string shared_hex;
  EllipticCurveType curve;
};

static const std::vector<TestVector> test_vector(
    {{"af33cd0629bc7e996320a3f40368f74de8704fa37b8fab69abaae280",
      "882092ccbba7930f419a8a4f9bb16978bbc3838729992559a6f2e2d7",
      "8346a60fc6f293ca5a0d2af68ba71d1dd389e5e40837942df3e43cbd",
      "7d96f9a3bd3c05cf5cc37feb8b9d5209d5c2597464dec3e9983743e8",
      EllipticCurveType::NIST_P224},
     {"700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
      "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
      "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
      "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
      EllipticCurveType::NIST_P256},
     {"a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b4"
      "00091adbf2d68c58e0c50066",
      "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32"
      "b060992b468c64766fc8437a",
      "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b20"
      "5da88cf699ab4d43c9cf98a1",
      "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e76"
      "6c40a2e3d4d6a04b25e533f1",
      EllipticCurveType::NIST_P384},
     {"000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b"
      "1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d",
      "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bd"
      "e99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676",
      "0000017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6"
      "564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
      "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72c"
      "c770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831",
      EllipticCurveType::NIST_P521}});

TEST_F(EcUtilTest, testBasic) {
  for (const TestVector& test : test_vector) {
    std::string pubx = test::HexDecodeOrDie(test.pubx_hex);
    std::string puby = test::HexDecodeOrDie(test.puby_hex);
    std::string priv = test::HexDecodeOrDie(test.priv_hex);
    std::string shared = test::HexDecodeOrDie(test.shared_hex);
    auto computed_shared =
        EcUtil::ComputeEcdhSharedSecret(test.curve, priv, pubx, puby);
    EXPECT_TRUE(computed_shared.ok());
    EXPECT_EQ(test.shared_hex, test::HexEncode(computed_shared.ValueOrDie()));

    // Modify the y coordinate of public key.
    puby = puby.substr(0, puby.length() - 1) +
           static_cast<char>(puby[puby.length() - 1] + 1);
    auto modified_shared =
        EcUtil::ComputeEcdhSharedSecret(test.curve, priv, pubx, puby);
    EXPECT_FALSE(modified_shared.ok());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
