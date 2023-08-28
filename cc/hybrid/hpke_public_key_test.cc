// Copyright 2023 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/hybrid/hpke_public_key.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "tink/hybrid/hpke_parameters.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  subtle::EllipticCurveType curve;
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  HpkeParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using HpkePublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    HpkePublicKeyTestSuite, HpkePublicKeyTest,
    Values(TestCase{subtle::EllipticCurveType::NIST_P256,
                    HpkeParameters::KemId::kDhkemP256HkdfSha256,
                    HpkeParameters::KdfId::kHkdfSha256,
                    HpkeParameters::AeadId::kAesGcm128,
                    HpkeParameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P384,
                    HpkeParameters::KemId::kDhkemP384HkdfSha384,
                    HpkeParameters::KdfId::kHkdfSha384,
                    HpkeParameters::AeadId::kAesGcm256,
                    HpkeParameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P521,
                    HpkeParameters::KemId::kDhkemP521HkdfSha512,
                    HpkeParameters::KdfId::kHkdfSha512,
                    HpkeParameters::AeadId::kChaChaPoly1305,
                    HpkeParameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(HpkePublicKeyTest, CreateNistCurvePublicKey) {
  TestCase test_case = GetParam();

  util::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());
  util::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(test_case.curve, ec_key->pub_x, ec_key->pub_y);
  ASSERT_THAT(ec_point, IsOk());
  util::StatusOr<std::string> public_key_bytes = internal::EcPointEncode(
      test_case.curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point->get());
  ASSERT_THAT(public_key_bytes, IsOk());

  util::StatusOr<HpkePublicKey> public_key =
      HpkePublicKey::Create(*params, *public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(*public_key_bytes));
}

TEST(HpkePublicKeyTest, CreateX25519PublicKey) {
  util::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST_P(HpkePublicKeyTest, CreateNistCurvePublicKeyWithInvalidLength) {
  TestCase test_case = GetParam();

  util::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());
  util::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(test_case.curve, ec_key->pub_x, ec_key->pub_y);
  ASSERT_THAT(ec_point, IsOk());
  util::StatusOr<std::string> public_key_bytes = internal::EcPointEncode(
      test_case.curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point->get());
  ASSERT_THAT(public_key_bytes, IsOk());

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes->substr(0, public_key_bytes->size() - 1),
      test_case.id_requirement, GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePublicKeyTest, CreateX25519PublicKeyWithInvalidLength) {
  util::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes.substr(0, public_key_bytes.size() - 1),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePublicKeyTest, CreateNistCurvePublicKeyWithInvalidPoint) {
  // Copied from "public point not on curve" Wycheproof test case in
  // https://github.com/google/wycheproof/blob/master/testvectors/ecdh_secp256k1_test.json.
  std::string invalid_point = absl::HexStringToBytes(
      "3056301006072a8648ce3d020106052b8104000a0342000449c248edc659e18482b71057"
      "48a4b95d3a46952a5ba72da0d702dc97a64e99799d8cff7a5c4b925e4360ece25ccf307d"
      "7a9a7063286bbd16ef64c65f546757e4");

  util::StatusOr<int32_t> point_size =
      internal::EcPointEncodingSizeInBytes(subtle::EllipticCurveType::NIST_P256,
                                           subtle::EcPointFormat::UNCOMPRESSED);
  ASSERT_THAT(point_size, IsOk());
  ASSERT_THAT(*point_size, testing::Lt(invalid_point.size()));

  std::string public_key_bytes =
      invalid_point.substr(invalid_point.size() - *point_size, *point_size);
  // Uncompressed point format starts with a 0x04-byte.
  ASSERT_THAT(public_key_bytes[0], Eq(0x04));

  util::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST(HpkePublicKeyTest, CreatePublicKeyWithInvalidIdRequirementFails) {
  util::StatusOr<HpkeParameters> no_prefix_params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  util::StatusOr<HpkeParameters> tink_params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  EXPECT_THAT(
      HpkePublicKey::Create(*no_prefix_params, public_key_bytes,
                            /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(HpkePublicKey::Create(*tink_params, public_key_bytes,
                                    /*id_requirement=*/absl::nullopt,
                                    GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkePublicKeyTest, NistCurvePublicKeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());
  util::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(test_case.curve, ec_key->pub_x, ec_key->pub_y);
  ASSERT_THAT(ec_point, IsOk());
  util::StatusOr<std::string> public_key_bytes = internal::EcPointEncode(
      test_case.curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point->get());
  ASSERT_THAT(public_key_bytes, IsOk());

  util::StatusOr<HpkePublicKey> public_key =
      HpkePublicKey::Create(*params, *public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<HpkePublicKey> other_public_key =
      HpkePublicKey::Create(*params, *public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(HpkePublicKeyTest, X25519PublicKeyEquals) {
  util::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<HpkePublicKey> other_public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(HpkePublicKeyTest, DifferentVariantNotEqual) {
  util::StatusOr<HpkeParameters> crunchy_params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(crunchy_params, IsOk());

  util::StatusOr<HpkeParameters> tink_params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *crunchy_params, public_key_bytes, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<HpkePublicKey> other_public_key = HpkePublicKey::Create(
      *tink_params, public_key_bytes, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Ed25519PublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  util::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes1 = subtle::Random::GetRandomBytes(32);
  std::string public_key_bytes2 = subtle::Random::GetRandomBytes(32);

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes1, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<HpkePublicKey> other_public_key = HpkePublicKey::Create(
      *params, public_key_bytes2, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Ed25519PublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaChaPoly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<HpkePublicKey> other_public_key = HpkePublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/0x02030405,
      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
