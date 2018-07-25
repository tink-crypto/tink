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

#include "tink/subtle/subtle_util_boringssl.h"

#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "include/rapidjson/document.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ec_util.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/x509.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

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
     {EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
      "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec66"
      "19b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
      "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327ac"
      "aac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
      "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec"
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

TEST(SubtleUtilBoringSSLTest, testEcPointEncode) {
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
    EXPECT_EQ(1, EC_POINT_set_affine_coordinates_GFp(
        status_or_group.ValueOrDie(), point.get(), x.get(),
        y.get(), nullptr));
    auto status_or_string = SubtleUtilBoringSSL::EcPointEncode(
        test.curve, test.format, point.get());
    EXPECT_TRUE(status_or_string.ok());
    EXPECT_EQ(test.encoded_hex, test::HexEncode(status_or_string.ValueOrDie()));
  }
}

TEST(SubtleUtilBoringSSLTest, testEcPointDecode) {
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
    EXPECT_EQ(1, EC_POINT_set_affine_coordinates_GFp(
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

TEST(SubtleUtilBoringSSLTest, testValidateSignatureHash) {
  EXPECT_TRUE(
      SubtleUtilBoringSSL::ValidateSignatureHash(HashType::SHA256).ok());
  EXPECT_TRUE(
      SubtleUtilBoringSSL::ValidateSignatureHash(HashType::SHA512).ok());
  EXPECT_FALSE(SubtleUtilBoringSSL::ValidateSignatureHash(HashType::SHA1).ok());
  EXPECT_FALSE(
      SubtleUtilBoringSSL::ValidateSignatureHash(HashType::UNKNOWN_HASH).ok());
}

static std::string GetError() {
  auto err = ERR_peek_last_error();
  // Sometimes there is no error message on the stack.
  if (err == 0) {
    return "";
  }
  std::string lib(ERR_lib_error_string(err));
  std::string func(ERR_func_error_string(err));
  std::string reason(ERR_reason_error_string(err));
  return lib + ":" + func + ":" + reason;
}

// Test with test vectors from Wycheproof project.
bool WycheproofTest(const rapidjson::Value &root) {
  int errors = 0;
  for (const rapidjson::Value& test_group : root["testGroups"].GetArray()) {
    std::string curve_str = test_group["curve"].GetString();
    // Tink only supports secp256r1, secp384r1 or secp521r1.
    if (!(curve_str == "secp256r1" || curve_str == "secp384r1"
          || curve_str == "secp521r1")) {
      continue;
    }
    EllipticCurveType curve = WycheproofUtil::GetEllipticCurveType(
        test_group["curve"]);
    for (const rapidjson::Value& test : test_group["tests"].GetArray()) {
      std::string id = absl::StrCat(test["tcId"].GetInt());
      std::string comment = test["comment"].GetString();
      std::string pub_bytes = WycheproofUtil::GetBytes(test["public"]);
      std::string priv_bytes = WycheproofUtil::GetBytes(test["private"]);
      std::string expected_shared_bytes = WycheproofUtil::GetBytes(test["shared"]);
      std::string result = test["result"].GetString();
      EcPointFormat format = EcPointFormat::UNCOMPRESSED;
      for (const rapidjson::Value& flag : test["flags"].GetArray()) {
        if (std::string(flag.GetString()) == "CompressedPoint") {
          format = EcPointFormat::COMPRESSED;
        }
      }
      // Wycheproof's ECDH public key uses ASN encoding while Tink uses X9.62
      // format point encoding. For the purpose of testing, we note the
      // followings:
      //  + The prefix of ASN encoding contains curve name, so we can skip test
      //  vector with "UnnamedCurve".
      //  + The suffix of ASN encoding is X9.62 format point encoding.
      // TODO(quannguyen): Use X9.62 test vectors once it's available.
      bool skip = false;
      for (const rapidjson::Value& flag : test["flags"].GetArray()) {
        if (std::string(flag.GetString()) == "UnnamedCurve") {
          skip = true;
          break;
        }
      }
      if (skip) {
        continue;
      }
      auto status_or_point_size = EcUtil::EncodingSizeInBytes(curve, format);
      if (!status_or_point_size.ok()) {
        continue;
      }
      size_t point_size = status_or_point_size.ValueOrDie();
      if (point_size > pub_bytes.size()) {
        continue;
      }
      pub_bytes = pub_bytes.substr(pub_bytes.size() - point_size, point_size);
      auto status_or_ec_point = SubtleUtilBoringSSL
          ::EcPointDecode(curve, format, pub_bytes);
      if (!status_or_ec_point.ok()) {
        if (result == "valid") {
          ADD_FAILURE() << "Could not decode public key with tcId:" << id
                        << " error:" << GetError()
                        << status_or_ec_point.status();
        }
        continue;
      }
      bssl::UniquePtr<EC_POINT> pub_key(status_or_ec_point.ValueOrDie());
      bssl::UniquePtr<BIGNUM> priv_key(
          BN_bin2bn(reinterpret_cast<const unsigned char*>(
              priv_bytes.data()), priv_bytes.size(), nullptr));
      auto status_or_shared = SubtleUtilBoringSSL
          ::ComputeEcdhSharedSecret(curve, priv_key.get(), pub_key.get());
      if (status_or_shared.ok()) {
        std::string shared = status_or_shared.ValueOrDie();
        if (result == "invalid") {
          ADD_FAILURE() << "Computed shared secret with invalid test vector"
                        << ", tcId= " << id;
          errors++;
        } else if (shared != expected_shared_bytes) {
          ADD_FAILURE() << "Computed wrong shared secret with tcId: " << id;
          errors++;
        }
      } else {
        if (result == "valid" || result == "acceptable") {
          ADD_FAILURE() << "Could not compute shared secret with tcId:" << id;
          errors++;
        }
      }
    }
  }
  return errors == 0;
}



TEST(SubtleUtilBoringSSLTest, testComputeEcdhSharedSecretWithWycheproofTest) {
  ASSERT_TRUE(WycheproofTest(*WycheproofUtil
                             ::ReadTestVectors("ecdh_test.json")));
  ASSERT_TRUE(WycheproofTest(*WycheproofUtil
                             ::ReadTestVectors("ecdh_secp256r1_test.json")));
  ASSERT_TRUE(WycheproofTest(*WycheproofUtil
                             ::ReadTestVectors("ecdh_secp384r1_test.json")));
  ASSERT_TRUE(WycheproofTest(*WycheproofUtil
                             ::ReadTestVectors("ecdh_secp521r1_test.json")));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
