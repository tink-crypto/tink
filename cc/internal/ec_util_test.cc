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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/types/span.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::EllipticCurveType;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::ElementsAreArray;
using ::testing::Not;

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
  ASSERT_EQ(ec_key.curve, subtle::EllipticCurveType::CURVE25519);

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

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
