// Copyright 2024 Google LLC
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

#include "tink/hybrid/ecies_parameters.h"

#include <memory>
#include <string>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Combine;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kSalt = "2024ab";

struct VariantWithIdRequirement {
  EciesParameters::Variant variant;
  bool has_id_requirement;
};

using EciesParametersTest = TestWithParam<
    std::tuple<EciesParameters::CurveType, EciesParameters::HashType,
               EciesParameters::PointFormat, EciesParameters::DemId,
               VariantWithIdRequirement>>;

INSTANTIATE_TEST_SUITE_P(
    EciesParametersTestSuite, EciesParametersTest,
    Combine(Values(EciesParameters::CurveType::kNistP256,
                   EciesParameters::CurveType::kNistP384,
                   EciesParameters::CurveType::kNistP521),
            Values(EciesParameters::HashType::kSha1,
                   EciesParameters::HashType::kSha224,
                   EciesParameters::HashType::kSha256,
                   EciesParameters::HashType::kSha384,
                   EciesParameters::HashType::kSha512),
            Values(EciesParameters::PointFormat::kCompressed,
                   EciesParameters::PointFormat::kUncompressed,
                   EciesParameters::PointFormat::kLegacyUncompressed),
            Values(EciesParameters::DemId::kAes128GcmRaw,
                   EciesParameters::DemId::kAes256GcmRaw,
                   EciesParameters::DemId::kAes256SivRaw,
                   EciesParameters::DemId::kXChaCha20Poly1305Raw),
            Values(VariantWithIdRequirement{EciesParameters::Variant::kTink,
                                            /*has_id_requirement=*/true},
                   VariantWithIdRequirement{EciesParameters::Variant::kCrunchy,
                                            /*has_id_requirement=*/true},
                   VariantWithIdRequirement{EciesParameters::Variant::kNoPrefix,
                                            /*has_id_requirement=*/false})));

TEST_P(EciesParametersTest, Build) {
  EciesParameters::CurveType curve_type;
  EciesParameters::HashType hash_type;
  EciesParameters::PointFormat point_format;
  EciesParameters::DemId dem_id;
  VariantWithIdRequirement variant;
  std::tie(curve_type, hash_type, point_format, dem_id, variant) = GetParam();
  const std::string salt = absl::HexStringToBytes(kSalt);

  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(curve_type)
          .SetHashType(hash_type)
          .SetNistCurvePointFormat(point_format)
          .SetDemId(dem_id)
          .SetSalt(salt)
          .SetVariant(variant.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetCurveType(), Eq(curve_type));
  EXPECT_THAT(parameters->GetHashType(), Eq(hash_type));
  EXPECT_THAT(parameters->GetNistCurvePointFormat(), Eq(point_format));
  EXPECT_THAT(parameters->GetDemId(), Eq(dem_id));
  EXPECT_THAT(parameters->GetSalt(), Eq(salt));
  EXPECT_THAT(parameters->GetVariant(), Eq(variant.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(variant.has_id_requirement));
}

TEST(EciesParametersTest, BuildWithX25519Curve) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetCurveType(),
              Eq(EciesParameters::CurveType::kX25519));
  EXPECT_THAT(parameters->GetHashType(),
              Eq(EciesParameters::HashType::kSha256));
  EXPECT_THAT(parameters->GetNistCurvePointFormat(), Eq(absl::nullopt));
  EXPECT_THAT(parameters->GetDemId(),
              Eq(EciesParameters::DemId::kAes256SivRaw));
  EXPECT_THAT(parameters->GetSalt(), Eq(absl::HexStringToBytes(kSalt)));
  EXPECT_THAT(parameters->GetVariant(), Eq(EciesParameters::Variant::kTink));
  EXPECT_THAT(parameters->HasIdRequirement(), IsTrue());
}

TEST(EciesParametersTest, BuildWithInvalidCurveTypeFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(
              EciesParameters::CurveType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithoutCurveTypeFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithInvalidHashTypeFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(
              EciesParameters::HashType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithoutHashTypeFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithInvalidPointFormatFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(
              EciesParameters::PointFormat::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithNistCurveWithoutPointFormatFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithX25519WithPointFormatFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kCompressed)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithInvalidDemIdFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::
                        kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithoutDemIdFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithEmptySaltSucceeds) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt("")
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetSalt(), Eq(absl::nullopt));
}

TEST(EciesParametersTest, BuildWithoutSaltSucceeds) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetSalt(), Eq(absl::nullopt));
}

TEST(EciesParametersTest, BuildWithInvalidVariantFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesParametersTest, BuildWithoutVariantFails) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519ParametersTest, CopyConstructor) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EciesParameters copy(*parameters);

  EXPECT_THAT(copy.GetCurveType(), Eq(EciesParameters::CurveType::kNistP256));
  EXPECT_THAT(copy.GetHashType(), Eq(EciesParameters::HashType::kSha256));
  EXPECT_THAT(copy.GetNistCurvePointFormat(),
              Eq(EciesParameters::PointFormat::kUncompressed));
  EXPECT_THAT(copy.GetDemId(), Eq(EciesParameters::DemId::kAes256SivRaw));
  EXPECT_THAT(copy.GetSalt(), Eq(absl::HexStringToBytes(kSalt)));
  EXPECT_THAT(copy.GetVariant(), Eq(EciesParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(Ed25519ParametersTest, CopyAssignment) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EciesParameters copy = *parameters;

  EXPECT_THAT(copy.GetCurveType(), Eq(EciesParameters::CurveType::kNistP256));
  EXPECT_THAT(copy.GetHashType(), Eq(EciesParameters::HashType::kSha256));
  EXPECT_THAT(copy.GetNistCurvePointFormat(),
              Eq(EciesParameters::PointFormat::kUncompressed));
  EXPECT_THAT(copy.GetDemId(), Eq(EciesParameters::DemId::kAes256SivRaw));
  EXPECT_THAT(copy.GetSalt(), Eq(absl::HexStringToBytes(kSalt)));
  EXPECT_THAT(copy.GetVariant(), Eq(EciesParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST_P(EciesParametersTest, ParametersEqual) {
  EciesParameters::CurveType curve_type;
  EciesParameters::HashType hash_type;
  EciesParameters::PointFormat point_format;
  EciesParameters::DemId dem_id;
  VariantWithIdRequirement variant;
  std::tie(curve_type, hash_type, point_format, dem_id, variant) = GetParam();
  const std::string salt = absl::HexStringToBytes(kSalt);

  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(curve_type)
          .SetHashType(hash_type)
          .SetNistCurvePointFormat(point_format)
          .SetDemId(dem_id)
          .SetSalt(salt)
          .SetVariant(variant.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesParameters> other_parameters =
      EciesParameters::Builder()
          .SetCurveType(curve_type)
          .SetHashType(hash_type)
          .SetNistCurvePointFormat(point_format)
          .SetDemId(dem_id)
          .SetSalt(salt)
          .SetVariant(variant.variant)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(EciesParametersTest, CurveTypeNotEqual) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesParameters> other_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP384)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EciesParametersTest, HashTypeNotEqual) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesParameters> other_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha384)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EciesParametersTest, PointFormatNotEqual) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesParameters> other_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kCompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EciesParametersTest, DemIdNotEqual) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesParameters> other_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EciesParametersTest, SaltNotEqual) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes("2024ab"))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesParameters> other_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes("2024xy"))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EciesParametersTest, EmptySaltAndNoSaltEqual) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesParameters> other_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(""))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
}

TEST(EciesParametersTest, VariantNotEqual) {
  util::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<EciesParameters> other_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(EciesParametersTest, CreateAes128GcmRawDemParameters) {
  util::StatusOr<EciesParameters> ecies_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(ecies_parameters, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> dem_parameters =
      ecies_parameters->CreateDemParameters();
  ASSERT_THAT(dem_parameters, IsOk());

  const AesGcmParameters* aes_128_gcm_parameters =
      reinterpret_cast<const AesGcmParameters*>((dem_parameters)->get());
  ASSERT_THAT(aes_128_gcm_parameters, NotNull());
  EXPECT_THAT(aes_128_gcm_parameters->KeySizeInBytes(), Eq(16));
  EXPECT_THAT(aes_128_gcm_parameters->IvSizeInBytes(), Eq(12));
  EXPECT_THAT(aes_128_gcm_parameters->TagSizeInBytes(), Eq(16));
  EXPECT_THAT(aes_128_gcm_parameters->GetVariant(),
              Eq(AesGcmParameters::Variant::kNoPrefix));
}

TEST(EciesParametersTest, CreateAes256GcmRawDemParameters) {
  util::StatusOr<EciesParameters> ecies_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256GcmRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(ecies_parameters, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> dem_parameters =
      ecies_parameters->CreateDemParameters();
  ASSERT_THAT(dem_parameters, IsOk());

  const AesGcmParameters* aes_256_gcm_parameters =
      reinterpret_cast<const AesGcmParameters*>((dem_parameters)->get());
  ASSERT_THAT(aes_256_gcm_parameters, NotNull());
  EXPECT_THAT(aes_256_gcm_parameters->KeySizeInBytes(), Eq(32));
  EXPECT_THAT(aes_256_gcm_parameters->IvSizeInBytes(), Eq(12));
  EXPECT_THAT(aes_256_gcm_parameters->TagSizeInBytes(), Eq(16));
  EXPECT_THAT(aes_256_gcm_parameters->GetVariant(),
              Eq(AesGcmParameters::Variant::kNoPrefix));
}

TEST(EciesParametersTest, CreateAes256SivRawDemParameters) {
  util::StatusOr<EciesParameters> ecies_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(ecies_parameters, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> dem_parameters =
      ecies_parameters->CreateDemParameters();
  ASSERT_THAT(dem_parameters, IsOk());

  const AesSivParameters* aes_256_siv_parameters =
      reinterpret_cast<const AesSivParameters*>((dem_parameters)->get());
  ASSERT_THAT(aes_256_siv_parameters, NotNull());
  EXPECT_THAT(aes_256_siv_parameters->KeySizeInBytes(), Eq(64));
  EXPECT_THAT(aes_256_siv_parameters->GetVariant(),
              Eq(AesSivParameters::Variant::kNoPrefix));
}

TEST(EciesParametersTest, CreateXChaCha20Poly1305RawDemParameters) {
  util::StatusOr<EciesParameters> ecies_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kXChaCha20Poly1305Raw)
          .SetSalt(absl::HexStringToBytes(kSalt))
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(ecies_parameters, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> dem_parameters =
      ecies_parameters->CreateDemParameters();
  ASSERT_THAT(dem_parameters, IsOk());

  const XChaCha20Poly1305Parameters* xchacha20_poly1305_parameters =
      reinterpret_cast<const XChaCha20Poly1305Parameters*>(
          (dem_parameters)->get());
  ASSERT_THAT(xchacha20_poly1305_parameters, NotNull());
  EXPECT_THAT(xchacha20_poly1305_parameters->GetVariant(),
              Eq(XChaCha20Poly1305Parameters::Variant::kNoPrefix));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
