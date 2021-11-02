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
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "openssl/cipher.h"
#include "openssl/curve25519.h"
#include "openssl/digest.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/nid.h"
#include "openssl/x509.h"
#include "include/rapidjson/document.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ec_util.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/secret_data.h"
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
using ::testing::NotNull;
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
    internal::SslUniquePtr<BIGNUM> x(
        BN_bin2bn(reinterpret_cast<const unsigned char*>(x_str.data()),
                  x_str.length(), nullptr));
    internal::SslUniquePtr<BIGNUM> y(
        BN_bin2bn(reinterpret_cast<const unsigned char*>(y_str.data()),
                  y_str.length(), nullptr));
    auto status_or_group = SubtleUtilBoringSSL::GetEcGroup(test.curve);
    internal::SslUniquePtr<EC_POINT> point(
        EC_POINT_new(status_or_group.ValueOrDie()));
    EXPECT_EQ(1, EC_POINT_set_affine_coordinates_GFp(
                     status_or_group.ValueOrDie(), point.get(), x.get(),
                     y.get(), nullptr));
    auto encoded_or = SubtleUtilBoringSSL::EcPointEncode(
        test.curve, test.format, point.get());
    EXPECT_TRUE(encoded_or.ok());
    EXPECT_EQ(test.encoded_hex, test::HexEncode(encoded_or.ValueOrDie()));
  }
}

TEST(SubtleUtilBoringSSLTest, EcPointDecode) {
  for (const EncodingTestVector& test : encoding_test_vector) {
    std::string x_str = test::HexDecodeOrDie(test.x_hex);
    std::string y_str = test::HexDecodeOrDie(test.y_hex);
    std::string encoded_str = test::HexDecodeOrDie(test.encoded_hex);
    internal::SslUniquePtr<BIGNUM> x(
        BN_bin2bn(reinterpret_cast<const unsigned char*>(x_str.data()),
                  x_str.length(), nullptr));
    internal::SslUniquePtr<BIGNUM> y(
        BN_bin2bn(reinterpret_cast<const unsigned char*>(y_str.data()),
                  y_str.length(), nullptr));
    auto status_or_group = SubtleUtilBoringSSL::GetEcGroup(test.curve);
    internal::SslUniquePtr<EC_POINT> point(
        EC_POINT_new(status_or_group.ValueOrDie()));
    EXPECT_EQ(1, EC_POINT_set_affine_coordinates_GFp(
                     status_or_group.ValueOrDie(), point.get(), x.get(),
                     y.get(), nullptr));
    auto status_or_ec_point = SubtleUtilBoringSSL::EcPointDecode(
        test.curve, test.format, encoded_str);
    EXPECT_TRUE(status_or_ec_point.ok());
    EXPECT_EQ(0, EC_POINT_cmp(status_or_group.ValueOrDie(), point.get(),
                              status_or_ec_point.ValueOrDie().get(), nullptr));
    // Modify the 1st byte.
    encoded_str = std::string("0") + encoded_str.substr(1);
    auto status_or_ec_point2 = SubtleUtilBoringSSL::EcPointDecode(
        test.curve, test.format, encoded_str);
    EXPECT_FALSE(status_or_ec_point2.ok());
    EXPECT_LE(0, status_or_ec_point2.status().message().find(
                     "point should start with"));
  }
}

TEST(SubtleUtilBoringSSLTest, GetCurveSuccess) {
  EC_GROUP* p256_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_GROUP* p384_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  EC_GROUP* p521_group = EC_GROUP_new_by_curve_name(NID_secp521r1);

  auto p256_curve = SubtleUtilBoringSSL::GetCurve(p256_group);
  auto p384_curve = SubtleUtilBoringSSL::GetCurve(p384_group);
  auto p521_curve = SubtleUtilBoringSSL::GetCurve(p521_group);

  EXPECT_THAT(p256_curve.status(), util::OkStatus());
  EXPECT_THAT(p384_curve.status(), util::OkStatus());
  EXPECT_THAT(p521_curve.status(), util::OkStatus());

  EXPECT_EQ(p256_curve.ValueOrDie(), EllipticCurveType::NIST_P256);
  EXPECT_EQ(p384_curve.ValueOrDie(), EllipticCurveType::NIST_P384);
  EXPECT_EQ(p521_curve.ValueOrDie(), EllipticCurveType::NIST_P521);
}

TEST(SubtleUtilBoringSSLTest, GetCurveUnimplemented) {
  EC_GROUP* unsupported_group = EC_GROUP_new_by_curve_name(NID_secp224r1);

  EXPECT_THAT(SubtleUtilBoringSSL::GetCurve(unsupported_group).status(),
              StatusIs(util::error::UNIMPLEMENTED));
}

TEST(SubtleUtilBoringSSLTest, ValidateSignatureHash) {
  EXPECT_TRUE(
      SubtleUtilBoringSSL::ValidateSignatureHash(HashType::SHA256).ok());
  EXPECT_TRUE(
      SubtleUtilBoringSSL::ValidateSignatureHash(HashType::SHA384).ok());
  EXPECT_TRUE(
      SubtleUtilBoringSSL::ValidateSignatureHash(HashType::SHA512).ok());
  EXPECT_FALSE(SubtleUtilBoringSSL::ValidateSignatureHash(HashType::SHA1).ok());
  EXPECT_FALSE(
      SubtleUtilBoringSSL::ValidateSignatureHash(HashType::SHA224).ok());
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
      std::string expected_shared_bytes =
          WycheproofUtil::GetBytes(test["shared"]);
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
      internal::SslUniquePtr<EC_POINT> pub_key =
          std::move(status_or_ec_point.ValueOrDie());
      internal::SslUniquePtr<BIGNUM> priv_key(
          BN_bin2bn(reinterpret_cast<const unsigned char*>(priv_bytes.data()),
                    priv_bytes.size(), nullptr));
      auto status_or_shared = SubtleUtilBoringSSL ::ComputeEcdhSharedSecret(
          curve, priv_key.get(), pub_key.get());
      if (status_or_shared.ok()) {
        util::SecretData shared = status_or_shared.ValueOrDie();
        if (result == "invalid") {
          ADD_FAILURE() << "Computed shared secret with invalid test vector"
                        << ", tcId= " << id;
          errors++;
        } else if (util::SecretDataAsStringView(shared) !=
                   expected_shared_bytes) {
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





TEST(CreatesNewEd25519KeyPairTest, BoringSSLPrivateKeySuffix) {
  // Generate a new key pair.
  uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t out_private_key[ED25519_PRIVATE_KEY_LEN];

  ED25519_keypair(out_public_key, out_private_key);
  std::string pk = std::string(reinterpret_cast<const char*>(out_public_key),
                               ED25519_PUBLIC_KEY_LEN);
  std::string sk = std::string(reinterpret_cast<const char*>(out_private_key),
                               ED25519_PRIVATE_KEY_LEN);
  ASSERT_EQ(pk.length(), 32);
  ASSERT_EQ(sk.length(), 64);
  // BoringSSL's ED25519_keypair returns a private key with the last 32-bytes
  // equal to the public key. If this changes you must update
  // SubtleUtilBoringSSL::GetNewEd25519Key().
  ASSERT_EQ(sk.substr(32, std::string::npos), pk);
}

TEST(CreatesNewEd25519KeyPairTest, KeyIsWellFormed) {
  auto keypair = SubtleUtilBoringSSL::GetNewEd25519Key();
  ASSERT_EQ(keypair->public_key.length(), 32);
  ASSERT_EQ(keypair->private_key.length(), 32);
  ASSERT_TRUE(keypair->public_key != keypair->private_key);
}

TEST(CreatesNewEd25519KeyPairTest, GeneratesDifferentKeysEveryTime) {
  auto keypair1 = SubtleUtilBoringSSL::GetNewEd25519Key();
  auto keypair2 = SubtleUtilBoringSSL::GetNewEd25519Key();
  ASSERT_NE(keypair1->public_key, keypair2->public_key);
  ASSERT_NE(keypair1->private_key, keypair2->private_key);
  ASSERT_NE(keypair1->public_key, keypair1->private_key);
}

TEST(CreateNewX25519KeyTest, KeyIsWellFormed) {
  auto ec_key_or_status =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::CURVE25519);
  ASSERT_THAT(ec_key_or_status.status(), IsOk());
  auto ec_key = ec_key_or_status.ValueOrDie();
  EXPECT_EQ(ec_key.curve, EllipticCurveType::CURVE25519);
  EXPECT_EQ(ec_key.pub_x.length(), X25519_PUBLIC_VALUE_LEN);
  EXPECT_TRUE(ec_key.pub_y.empty());
  EXPECT_EQ(ec_key.priv.size(), X25519_PRIVATE_KEY_LEN);
}

TEST(CreateNewX25519KeyTest, GeneratesDifferentKeysEveryTime) {
  auto keypair1 = SubtleUtilBoringSSL::GenerateNewX25519Key();
  auto keypair2 = SubtleUtilBoringSSL::GenerateNewX25519Key();

  EXPECT_FALSE(std::equal(keypair1->private_key,
                          &keypair1->private_key[X25519_PRIVATE_KEY_LEN],
                          keypair2->private_key));
  EXPECT_FALSE(std::equal(keypair1->public_value,
                          &keypair1->public_value[X25519_PUBLIC_VALUE_LEN],
                          keypair2->public_value));
}

TEST(EcKeyFromX25519KeyTest, RoundTripKey) {
  auto x25519_key = SubtleUtilBoringSSL::GenerateNewX25519Key();
  ASSERT_THAT(x25519_key, NotNull());
  auto ec_key = SubtleUtilBoringSSL::EcKeyFromX25519Key(x25519_key.get());
  ASSERT_EQ(ec_key.curve, EllipticCurveType::CURVE25519);

  auto roundtrip_key_or_status =
      SubtleUtilBoringSSL::X25519KeyFromEcKey(ec_key);
  ASSERT_THAT(roundtrip_key_or_status.status(), IsOk());

  auto roundtrip_key = std::move(roundtrip_key_or_status.ValueOrDie());
  EXPECT_TRUE(std::equal(x25519_key->private_key,
                         &x25519_key->private_key[X25519_PRIVATE_KEY_LEN],
                         roundtrip_key->private_key));
  EXPECT_TRUE(std::equal(x25519_key->public_value,
                         &x25519_key->public_value[X25519_PUBLIC_VALUE_LEN],
                         roundtrip_key->public_value));
}

TEST(X25519KeyFromEcKeyTest, RejectNistPCurves) {
  auto ec_key_or_status =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key_or_status.status(), IsOk());

  auto x25519_key_or_status =
      SubtleUtilBoringSSL::X25519KeyFromEcKey(ec_key_or_status.ValueOrDie());
  EXPECT_THAT(x25519_key_or_status.status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

using NistCurveParamTest = ::testing::TestWithParam<EllipticCurveType>;
INSTANTIATE_TEST_SUITE_P(NistCurvesParams, NistCurveParamTest,
                         ::testing::Values(NIST_P256, NIST_P384, NIST_P521));

TEST_P(NistCurveParamTest, KeysFromDifferentSeedAreDifferent) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData seed1 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  util::SecretData seed2 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("0f0e0d0c0b0a09080706050403020100"));

  crypto::tink::subtle::EllipticCurveType curve = GetParam();

  crypto::tink::util::StatusOr<SubtleUtilBoringSSL::EcKey> keypair1 =
      SubtleUtilBoringSSL::GetNewEcKeyFromSeed(curve, seed1);
  crypto::tink::util::StatusOr<SubtleUtilBoringSSL::EcKey> keypair2 =
      SubtleUtilBoringSSL::GetNewEcKeyFromSeed(curve, seed2);

  ASSERT_THAT(keypair1.status(), IsOk());
  ASSERT_THAT(keypair2.status(), IsOk());

  EXPECT_NE(keypair1->priv, keypair2->priv);
  EXPECT_NE(keypair1->pub_x, keypair2->pub_x);
  EXPECT_NE(keypair1->pub_y, keypair2->pub_y);
}

TEST_P(NistCurveParamTest, SameSeedGivesSameKey) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData seed1 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));

  auto curve = GetParam();

  auto keypair1_or_status =
      SubtleUtilBoringSSL::GetNewEcKeyFromSeed(curve, seed1);
  auto keypair2_or_status =
      SubtleUtilBoringSSL::GetNewEcKeyFromSeed(curve, seed1);

  ASSERT_THAT(keypair1_or_status.status(), IsOk());
  ASSERT_THAT(keypair2_or_status.status(), IsOk());

  auto keypair1 = keypair1_or_status.ValueOrDie();
  auto keypair2 = keypair2_or_status.ValueOrDie();

  EXPECT_EQ(keypair1.priv, keypair2.priv);
  EXPECT_EQ(keypair1.pub_x, keypair2.pub_x);
  EXPECT_EQ(keypair1.pub_y, keypair2.pub_y);
}

TEST(SubtleUtilBoringSSLTest, GenerationWithSeedFailsWithWrongCurve) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::SecretData seed = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));

  auto keypair_or_status = SubtleUtilBoringSSL::GetNewEcKeyFromSeed(
      EllipticCurveType::CURVE25519, seed);

  EXPECT_THAT(keypair_or_status.status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(SublteUtilBoringSSLTest, GetCipherForKeySize) {
  EXPECT_EQ(SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(16),
            EVP_aes_128_ctr());
  EXPECT_EQ(SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(32),
            EVP_aes_256_ctr());
  EXPECT_EQ(SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(64), nullptr);
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

INSTANTIATE_TEST_SUITE_P(
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
