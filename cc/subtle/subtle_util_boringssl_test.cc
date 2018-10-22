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

#include <algorithm>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "openssl/digest.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "include/rapidjson/document.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ec_util.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::StrEq;

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

TEST(SubtleUtilBoringSSLTest, EcPointEncode) {
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

TEST(SubtleUtilBoringSSLTest, EcPointDecode) {
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

TEST(SubtleUtilBoringSSLTest, Bn2strAndStr2bn) {
  int len = 8;
  std::string bn_str[6] = {"0000000000000000", "0000000000000001",
                      "1000000000000000", "ffffffffffffffff",
                      "0fffffffffffffff", "00ffffffffffffff"};
  for (const std::string& s : bn_str) {
    auto status_or_bn = SubtleUtilBoringSSL::str2bn(test::HexDecodeOrDie(s));
    EXPECT_TRUE(status_or_bn.ok());
    auto status_or_str =
        SubtleUtilBoringSSL::bn2str(status_or_bn.ValueOrDie().get(), len);
    EXPECT_TRUE(status_or_str.ok());
    EXPECT_EQ(test::HexDecodeOrDie(s), status_or_str.ValueOrDie());
  }
}

TEST(SubtleUtilBoringSSLTest, ValidateSignatureHash) {
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
bool WycheproofTest(const rapidjson::Value& root) {
  int errors = 0;
  for (const rapidjson::Value& test_group : root["testGroups"].GetArray()) {
    std::string curve_str = test_group["curve"].GetString();
    // Tink only supports secp256r1, secp384r1 or secp521r1.
    if (!(curve_str == "secp256r1" || curve_str == "secp384r1" ||
          curve_str == "secp521r1")) {
      continue;
    }
    EllipticCurveType curve =
        WycheproofUtil::GetEllipticCurveType(test_group["curve"]);
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
      auto status_or_ec_point =
          SubtleUtilBoringSSL ::EcPointDecode(curve, format, pub_bytes);
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
          BN_bin2bn(reinterpret_cast<const unsigned char*>(priv_bytes.data()),
                    priv_bytes.size(), nullptr));
      auto status_or_shared = SubtleUtilBoringSSL ::ComputeEcdhSharedSecret(
          curve, priv_key.get(), pub_key.get());
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

TEST(SubtleUtilBoringSSLTest, ComputeEcdhSharedSecretWithWycheproofTest) {
// placeholder_disabled_subtle_test, please ignore
  ASSERT_TRUE(WycheproofTest(
      *WycheproofUtil ::ReadTestVectors("ecdh_test.json")));
  ASSERT_TRUE(WycheproofTest(
      *WycheproofUtil ::ReadTestVectors("ecdh_secp256r1_test.json")));
  ASSERT_TRUE(WycheproofTest(
      *WycheproofUtil ::ReadTestVectors("ecdh_secp384r1_test.json")));
  ASSERT_TRUE(WycheproofTest(
      *WycheproofUtil ::ReadTestVectors("ecdh_secp521r1_test.json")));
}

TEST(CreatesNewRsaKeyPairTest, BasicSanityChecks) {
  SubtleUtilBoringSSL::RsaPublicKey public_key;
  SubtleUtilBoringSSL::RsaPrivateKey private_key;

  bssl::UniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  ASSERT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(2048, e.get(), &private_key,
                                                    &public_key),
              IsOk());
  EXPECT_THAT(private_key.n, Not(IsEmpty()));
  EXPECT_THAT(private_key.e, Not(IsEmpty()));
  EXPECT_THAT(private_key.d, Not(IsEmpty()));

  EXPECT_THAT(private_key.p, Not(IsEmpty()));
  EXPECT_THAT(private_key.q, Not(IsEmpty()));
  EXPECT_THAT(private_key.dp, Not(IsEmpty()));
  EXPECT_THAT(private_key.dq, Not(IsEmpty()));
  EXPECT_THAT(private_key.crt, Not(IsEmpty()));

  EXPECT_THAT(public_key.n, Not(IsEmpty()));
  EXPECT_THAT(public_key.e, Not(IsEmpty()));

  EXPECT_EQ(public_key.n, private_key.n);
  EXPECT_EQ(public_key.e, private_key.e);
}

TEST(CreatesNewRsaKeyPairTest, FailsOnLargeE) {
  // OpenSSL requires the "e" value to be at most 32 bits.
  SubtleUtilBoringSSL::RsaPublicKey public_key;
  SubtleUtilBoringSSL::RsaPrivateKey private_key;

  bssl::UniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), 1L << 33);
  ASSERT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(2048, e.get(), &private_key,
                                                    &public_key),
              StatusIs(util::error::INTERNAL));
}

TEST(CreatesNewRsaKeyPairTest, KeyIsWellFormed) {
  SubtleUtilBoringSSL::RsaPublicKey public_key;
  SubtleUtilBoringSSL::RsaPrivateKey private_key;
  bssl::UniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  ASSERT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(2048, e.get(), &private_key,
                                                    &public_key),
              IsOk());
  auto n = std::move(SubtleUtilBoringSSL::str2bn(private_key.n).ValueOrDie());
  auto d = std::move(SubtleUtilBoringSSL::str2bn(private_key.d).ValueOrDie());
  auto p = std::move(SubtleUtilBoringSSL::str2bn(private_key.p).ValueOrDie());
  auto q = std::move(SubtleUtilBoringSSL::str2bn(private_key.q).ValueOrDie());
  auto dp = std::move(SubtleUtilBoringSSL::str2bn(private_key.dp).ValueOrDie());
  auto dq = std::move(SubtleUtilBoringSSL::str2bn(private_key.dq).ValueOrDie());
  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());

  // Check n = p * q.
  {
    auto n_calc = bssl::UniquePtr<BIGNUM>(BN_new());
    ASSERT_TRUE(BN_mul(n_calc.get(), p.get(), q.get(), ctx.get()));
    ASSERT_TRUE(BN_equal_consttime(n_calc.get(), n.get()));
  }

  // Check n size >= 2048 bit.
  EXPECT_GE(BN_num_bits(n.get()), 2048);

  // dp = d mod (p - 1)
  {
    auto pm1 = bssl::UniquePtr<BIGNUM>(BN_dup(p.get()));
    ASSERT_TRUE(BN_sub_word(pm1.get(), 1));
    auto dp_calc = bssl::UniquePtr<BIGNUM>(BN_new());
    ASSERT_TRUE(BN_mod(dp_calc.get(), d.get(), pm1.get(), ctx.get()));

    ASSERT_TRUE(BN_equal_consttime(dp_calc.get(), dp.get()));
  }

  // dq = d mod (q - 1)
  {
    auto qm1 = bssl::UniquePtr<BIGNUM>(BN_dup(q.get()));
    ASSERT_TRUE(BN_sub_word(qm1.get(), 1));
    auto dq_calc = bssl::UniquePtr<BIGNUM>(BN_new());
    ASSERT_TRUE(BN_mod(dq_calc.get(), d.get(), qm1.get(), ctx.get()));

    ASSERT_TRUE(BN_equal_consttime(dq_calc.get(), dq.get()));
  }
}

TEST(CreatesNewRsaKeyPairTest, GeneratesDifferentKeysEveryTime) {
  SubtleUtilBoringSSL::RsaPublicKey public_key;
  bssl::UniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);

  std::vector<SubtleUtilBoringSSL::RsaPrivateKey> generated_keys;
  std::generate_n(std::back_inserter(generated_keys), 4, [&]() {
    SubtleUtilBoringSSL::RsaPrivateKey private_key;
    EXPECT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(
                    2048, e.get(), &private_key, &public_key),
                IsOk());
    return private_key;
  });

  // Iterate through a two-element sliding windows, comparing two consecutive
  // elements in the list.
  for (std::size_t i = 0; i + 1 < generated_keys.size(); ++i) {
    const auto& left = generated_keys[i];
    const auto& right = generated_keys[i + 1];

    // The only fieldthat should be equal.
    ASSERT_EQ(left.e, right.e);

    ASSERT_NE(left.n, right.n);
    ASSERT_NE(left.d, right.d);

    ASSERT_NE(left.p, right.p);
    ASSERT_NE(left.q, right.q);
    ASSERT_NE(left.dp, right.dp);
    ASSERT_NE(left.dq, right.dq);
    ASSERT_NE(left.crt, right.crt);
  }
}

TEST(SubtleUtilBoringSSLTest, ValidateRsaModulusSize) {
  SubtleUtilBoringSSL::RsaPublicKey public_key;
  SubtleUtilBoringSSL::RsaPrivateKey private_key;
  bssl::UniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  ASSERT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(2048, e.get(), &private_key,
                                                    &public_key),
              IsOk());
  auto n_2048 =
      std::move(SubtleUtilBoringSSL::str2bn(private_key.n).ValueOrDie());
  ASSERT_THAT(
      SubtleUtilBoringSSL::ValidateRsaModulusSize(BN_num_bits(n_2048.get())),
      IsOk());

  ASSERT_THAT(SubtleUtilBoringSSL::GetNewRsaKeyPair(1024, e.get(), &private_key,
                                                    &public_key),
              IsOk());
  auto n_1024 =
      std::move(SubtleUtilBoringSSL::str2bn(private_key.n).ValueOrDie());
  ASSERT_THAT(
      SubtleUtilBoringSSL::ValidateRsaModulusSize(BN_num_bits(n_1024.get())),
      Not(IsOk()));
}

TEST(ComputeHashTest, AcceptsNullStringView) {
  auto null_hash =
      boringssl::ComputeHash(absl::string_view(nullptr, 0), *EVP_sha512());
  auto empty_hash = boringssl::ComputeHash("", *EVP_sha512());
  std::string str;
  auto empty_str_hash = boringssl::ComputeHash(str, *EVP_sha512());

  ASSERT_THAT(null_hash.status(), IsOk());
  ASSERT_THAT(empty_hash.status(), IsOk());
  ASSERT_THAT(empty_str_hash.status(), IsOk());

  EXPECT_EQ(null_hash.ValueOrDie(), empty_hash.ValueOrDie());
  EXPECT_EQ(null_hash.ValueOrDie(), empty_str_hash.ValueOrDie());
}

using ComputeHashSamplesTest = ::testing::TestWithParam<
    std::tuple<HashType, absl::string_view, absl::string_view>>;

INSTANTIATE_TEST_CASE_P(
    NistSampleCases, ComputeHashSamplesTest,
    ::testing::Values(
        std::make_tuple(
            HashType::SHA256, "af397a8b8dd73ab702ce8e53aa9f",
            "d189498a3463b18e846b8ab1b41583b0b7efc789dad8a7fb885bbf8fb5b45c5c"),
        std::make_tuple(
            HashType::SHA256, "59eb45bbbeb054b0b97334d53580ce03f699",
            "32c38c54189f2357e96bd77eb00c2b9c341ebebacc2945f97804f59a93238288"),
        std::make_tuple(
            HashType::SHA512,
            "16b17074d3e3d97557f9ed77d920b4b1bff4e845b345a922",
            "6884134582a760046433abcbd53db8ff1a89995862f305b887020f6da6c7b903a3"
            "14721e972bf438483f452a8b09596298a576c903c91df4a414c7bd20fd1d07"),
        std::make_tuple(
            HashType::SHA512,
            "7651ab491b8fa86f969d42977d09df5f8bee3e5899180b52c968b0db057a6f02a8"
            "86ad617a84915a",
            "f35e50e2e02b8781345f8ceb2198f068ba103476f715cfb487a452882c9f0de0c7"
            "20b2a088a39d06a8a6b64ce4d6470dfeadc4f65ae06672c057e29f14c4daf9")));

TEST_P(ComputeHashSamplesTest, ComputesHash) {
  const EVP_MD* hasher =
      SubtleUtilBoringSSL::EvpHash(std::get<0>(GetParam())).ValueOrDie();
  std::string data = absl::HexStringToBytes(std::get<1>(GetParam()));
  std::string expected_hash = absl::HexStringToBytes(std::get<2>(GetParam()));

  auto hash_or = boringssl::ComputeHash(data, *hasher);
  ASSERT_THAT(hash_or.status(), IsOk());
  std::string hash(reinterpret_cast<char*>(hash_or.ValueOrDie().data()),
              hash_or.ValueOrDie().size());
  EXPECT_THAT(hash, StrEq(expected_hash));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
