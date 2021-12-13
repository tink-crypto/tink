// Copyright 2021 Google LLC
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
#include "tink/internal/ec_util.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::EcPointFormat;
using ::crypto::tink::subtle::EllipticCurveType;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::ElementsAreArray;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

TEST(EcUtilTest, NewX25519KeyGeneratesNewKeyEveryTime) {
  util::StatusOr<std::unique_ptr<X25519Key>> keypair1 = NewX25519Key();
  ASSERT_THAT(keypair1.status(), IsOk());
  util::StatusOr<std::unique_ptr<X25519Key>> keypair2 = NewX25519Key();
  ASSERT_THAT(keypair2.status(), IsOk());

  auto priv_key1 =
      absl::MakeSpan((*keypair1)->private_key, X25519KeyPrivKeySize());
  auto priv_key2 =
      absl::MakeSpan((*keypair2)->private_key, X25519KeyPrivKeySize());
  auto pub_key1 =
      absl::MakeSpan((*keypair1)->public_value, X25519KeyPubKeySize());
  auto pub_key2 =
      absl::MakeSpan((*keypair2)->public_value, X25519KeyPubKeySize());
  EXPECT_THAT(priv_key1, Not(ElementsAreArray(priv_key2)));
  EXPECT_THAT(pub_key1, Not(ElementsAreArray(pub_key2)));
}

TEST(EcUtilTest, X25519KeyToEcKeyAndBack) {
  util::StatusOr<std::unique_ptr<X25519Key>> x25519_key = NewX25519Key();
  ASSERT_THAT(x25519_key.status(), IsOk());
  EcKey ec_key = EcKeyFromX25519Key(x25519_key->get());
  ASSERT_EQ(ec_key.curve, EllipticCurveType::CURVE25519);

  util::StatusOr<std::unique_ptr<X25519Key>> roundtrip_key =
      X25519KeyFromEcKey(ec_key);
  ASSERT_THAT(roundtrip_key.status(), IsOk());
  EXPECT_THAT(
      absl::MakeSpan((*x25519_key)->private_key, X25519KeyPrivKeySize()),
      ElementsAreArray(absl::MakeSpan((*roundtrip_key)->private_key,
                                      X25519KeyPrivKeySize())));
  EXPECT_THAT(
      absl::MakeSpan((*x25519_key)->public_value, X25519KeyPubKeySize()),
      ElementsAreArray(absl::MakeSpan((*roundtrip_key)->public_value,
                                      X25519KeyPubKeySize())));
}

struct EncodingTestVector {
  EcPointFormat format;
  std::string x_hex;
  std::string y_hex;
  std::string encoded_hex;
  EllipticCurveType curve;
};

const std::vector<EncodingTestVector> GetEncodingTestVectors() {
  return {
      {EcPointFormat::UNCOMPRESSED,
       "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
       "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
       "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327a"
       "caac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       "0400093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918e"
       "c6619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a00aa3fb2"
       "448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327acaac1fa4"
       "0424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       EllipticCurveType::NIST_P521},
      {EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
       "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
       "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
       "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327a"
       "caac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
       "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a00aa3fb244"
       "8335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327acaac1fa404"
       "24c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       EllipticCurveType::NIST_P521},
      {EcPointFormat::COMPRESSED,
       "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
       "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
       "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327a"
       "caac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf",
       "0300093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918e"
       "c6619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a",
       EllipticCurveType::NIST_P521}};
}

using EcUtilEncodeDecodePointTest = TestWithParam<EncodingTestVector>;

TEST_P(EcUtilEncodeDecodePointTest, EcPointEncode) {
  const EncodingTestVector& test = GetParam();
  util::StatusOr<SslUniquePtr<EC_POINT>> point =
      GetEcPoint(test.curve, absl::HexStringToBytes(test.x_hex),
                 absl::HexStringToBytes(test.y_hex));
  ASSERT_THAT(point.status(), IsOk());

  util::StatusOr<std::string> encoded_point =
      EcPointEncode(test.curve, test.format, point->get());
  ASSERT_THAT(encoded_point.status(), IsOk());
  EXPECT_EQ(test.encoded_hex, absl::BytesToHexString(*encoded_point));
}

TEST_P(EcUtilEncodeDecodePointTest, EcPointDecode) {
  const EncodingTestVector& test = GetParam();
  // Get the test point and its encoded version.
  util::StatusOr<SslUniquePtr<EC_POINT>> point =
      GetEcPoint(test.curve, absl::HexStringToBytes(test.x_hex),
                 absl::HexStringToBytes(test.y_hex));
  ASSERT_THAT(point.status(), IsOk());
  std::string encoded_str = absl::HexStringToBytes(test.encoded_hex);

  util::StatusOr<SslUniquePtr<EC_GROUP>> ec_group =
      EcGroupFromCurveType(test.curve);
  util::StatusOr<SslUniquePtr<EC_POINT>> ec_point =
      EcPointDecode(test.curve, test.format, encoded_str);
  ASSERT_THAT(ec_point.status(), IsOk());
  EXPECT_EQ(EC_POINT_cmp(ec_group->get(), point->get(), ec_point->get(),
                         /*ctx=*/nullptr),
            0);

  // Modifying the 1st byte decoding fails.
  encoded_str[0] = '0';
  util::StatusOr<SslUniquePtr<EC_POINT>> ec_point2 =
      EcPointDecode(test.curve, test.format, encoded_str);
  EXPECT_THAT(ec_point2.status(), Not(IsOk()));
  if (test.format == EcPointFormat::UNCOMPRESSED ||
      test.format == EcPointFormat::COMPRESSED) {
    EXPECT_THAT(std::string(ec_point2.status().message()),
                HasSubstr("point should start with"));
  }
}

INSTANTIATE_TEST_SUITE_P(
    EcUtilEncodeDecodePointTests, EcUtilEncodeDecodePointTest,
    ValuesIn(GetEncodingTestVectors()),
    [](const TestParamInfo<EcUtilEncodeDecodePointTest::ParamType>& info) {
      switch (info.param.format) {
        case EcPointFormat::UNCOMPRESSED:
          return "Uncompressed";
        case EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
          return "DoNotUseCrunchyUncompressed";
        case EcPointFormat::COMPRESSED:
          return "Compressed";
        default:
          return "Unknown";
      }
    });

TEST(EcUtilTest, CurveTypeFromEcGroupSuccess) {
  EC_GROUP* p256_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_GROUP* p384_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
  EC_GROUP* p521_group = EC_GROUP_new_by_curve_name(NID_secp521r1);

  util::StatusOr<EllipticCurveType> p256_curve =
      CurveTypeFromEcGroup(p256_group);
  util::StatusOr<EllipticCurveType> p384_curve =
      CurveTypeFromEcGroup(p384_group);
  util::StatusOr<EllipticCurveType> p521_curve =
      CurveTypeFromEcGroup(p521_group);

  ASSERT_THAT(p256_curve, IsOkAndHolds(EllipticCurveType::NIST_P256));
  ASSERT_THAT(p384_curve, IsOkAndHolds(EllipticCurveType::NIST_P384));
  ASSERT_THAT(p521_curve, IsOkAndHolds(EllipticCurveType::NIST_P521));
}

TEST(EcUtilTest, CurveTypeFromEcGroupUnimplemented) {
  EXPECT_THAT(
      CurveTypeFromEcGroup(EC_GROUP_new_by_curve_name(NID_secp224r1)).status(),
      StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(EcUtilTest, EcGroupFromCurveTypeSuccess) {
  util::StatusOr<SslUniquePtr<EC_GROUP>> p256_curve =
      EcGroupFromCurveType(EllipticCurveType::NIST_P256);
  util::StatusOr<SslUniquePtr<EC_GROUP>> p384_curve =
      EcGroupFromCurveType(EllipticCurveType::NIST_P384);
  util::StatusOr<SslUniquePtr<EC_GROUP>> p521_curve =
      EcGroupFromCurveType(EllipticCurveType::NIST_P521);
  ASSERT_THAT(p256_curve.status(), IsOk());
  ASSERT_THAT(p384_curve.status(), IsOk());
  ASSERT_THAT(p521_curve.status(), IsOk());

  SslUniquePtr<EC_GROUP> ssl_p256_group(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  SslUniquePtr<EC_GROUP> ssl_p384_group(
      EC_GROUP_new_by_curve_name(NID_secp384r1));
  SslUniquePtr<EC_GROUP> ssl_p521_group(
      EC_GROUP_new_by_curve_name(NID_secp521r1));

  EXPECT_EQ(
      EC_GROUP_cmp(p256_curve->get(), ssl_p256_group.get(), /*ctx=*/nullptr),
      0);
  EXPECT_EQ(
      EC_GROUP_cmp(p384_curve->get(), ssl_p384_group.get(), /*ctx=*/nullptr),
      0);
  EXPECT_EQ(
      EC_GROUP_cmp(p521_curve->get(), ssl_p521_group.get(), /*ctx=*/nullptr),
      0);
}

TEST(EcUtilTest, EcGroupFromCurveTypeUnimplemented) {
  EXPECT_THAT(EcGroupFromCurveType(EllipticCurveType::UNKNOWN_CURVE).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(EcUtilTest, GetEcPointReturnsAValidPoint) {
  SslUniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_secp521r1));
  const unsigned int kCurveSizeInBytes =
      (EC_GROUP_get_degree(group.get()) + 7) / 8;

  constexpr absl::string_view kXCoordinateHex =
      "00093057fb862f2ad2e82e581baeb3324e7b32946f2ba845a9beeed87d6995f54918ec6"
      "619b9931955d5a89d4d74adf1046bb362192f2ef6bd3e3d2d04dd1f87054a";
  constexpr absl::string_view kYCoordinateHex =
      "00aa3fb2448335f694e3cda4ae0cc71b1b2f2a206fa802d7262f19983c44674fe15327a"
      "caac1fa40424c395a6556cb8167312527fae5865ecffc14bbdc17da78cdcf";
  util::StatusOr<SslUniquePtr<EC_POINT>> point = GetEcPoint(
      EllipticCurveType::NIST_P521, absl::HexStringToBytes(kXCoordinateHex),
      absl::HexStringToBytes(kYCoordinateHex));
  ASSERT_THAT(point.status(), IsOk());

  // We check that we can decode this point and the result is the same as the
  // original coordinates.
  std::string xy;
  subtle::ResizeStringUninitialized(&xy, 2 * kCurveSizeInBytes);
  SslUniquePtr<BIGNUM> x(BN_new());
  SslUniquePtr<BIGNUM> y(BN_new());
  ASSERT_EQ(EC_POINT_get_affine_coordinates(group.get(), point->get(), x.get(),
                                            y.get(), /*ctx=*/nullptr),
            1);
  ASSERT_THAT(
      BignumToBinaryPadded(absl::MakeSpan(&xy[0], kCurveSizeInBytes), x.get()),
      IsOk());
  ASSERT_THAT(
      BignumToBinaryPadded(
          absl::MakeSpan(&xy[kCurveSizeInBytes], kCurveSizeInBytes), y.get()),
      IsOk());
  EXPECT_EQ(xy, absl::StrCat(absl::HexStringToBytes(kXCoordinateHex),
                             absl::HexStringToBytes(kYCoordinateHex)));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
