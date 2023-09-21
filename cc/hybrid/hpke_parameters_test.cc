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

#include "tink/hybrid/hpke_parameters.h"

#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
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
using ::testing::TestWithParam;
using ::testing::Values;

struct VariantWithIdRequirement {
  HpkeParameters::Variant variant;
  bool has_id_requirement;
};

using HpkeParametersTest =
    TestWithParam<std::tuple<HpkeParameters::KemId, HpkeParameters::KdfId,
                             HpkeParameters::AeadId, VariantWithIdRequirement>>;

INSTANTIATE_TEST_SUITE_P(
    HpkeParametersTestSuite, HpkeParametersTest,
    Combine(Values(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                   HpkeParameters::KemId::kDhkemP384HkdfSha384,
                   HpkeParameters::KemId::kDhkemP521HkdfSha512,
                   HpkeParameters::KemId::kDhkemX25519HkdfSha256),
            Values(HpkeParameters::KdfId::kHkdfSha256,
                   HpkeParameters::KdfId::kHkdfSha384,
                   HpkeParameters::KdfId::kHkdfSha512),
            Values(HpkeParameters::AeadId::kAesGcm128,
                   HpkeParameters::AeadId::kAesGcm256,
                   HpkeParameters::AeadId::kChaCha20Poly1305),
            Values(VariantWithIdRequirement{HpkeParameters::Variant::kTink,
                                            /*has_id_requirement=*/true},
                   VariantWithIdRequirement{HpkeParameters::Variant::kCrunchy,
                                            /*has_id_requirement=*/true},
                   VariantWithIdRequirement{HpkeParameters::Variant::kNoPrefix,
                                            /*has_id_requirement=*/false})));

TEST_P(HpkeParametersTest, Build) {
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  VariantWithIdRequirement variant;
  std::tie(kem_id, kdf_id, aead_id, variant) = GetParam();

  util::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(variant.variant)
                                                  .SetKemId(kem_id)
                                                  .SetKdfId(kdf_id)
                                                  .SetAeadId(aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetKemId(), Eq(kem_id));
  EXPECT_THAT(parameters->GetKdfId(), Eq(kdf_id));
  EXPECT_THAT(parameters->GetAeadId(), Eq(aead_id));
  EXPECT_THAT(parameters->GetVariant(), Eq(variant.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(variant.has_id_requirement));
}

TEST(HpkeParametersTest, BuildWithInvalidVariantFails) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithoutVariantFails) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithInvalidKemIdFails) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::
                        kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithoutKemIdFails) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithInvalidKdfIdFails) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::
                        kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithoutKdfIdFails) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithInvalidAeadIdFails) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::
                         kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithoutAeadIdFails) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519ParametersTest, CopyConstructor) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  HpkeParameters copy(*parameters);

  EXPECT_THAT(copy.GetVariant(), Eq(HpkeParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(Ed25519ParametersTest, CopyAssignment) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  HpkeParameters copy = *parameters;

  EXPECT_THAT(copy.GetVariant(), Eq(HpkeParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST_P(HpkeParametersTest, ParametersEquals) {
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  VariantWithIdRequirement variant;
  std::tie(kem_id, kdf_id, aead_id, variant) = GetParam();

  util::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(variant.variant)
                                                  .SetKemId(kem_id)
                                                  .SetKdfId(kdf_id)
                                                  .SetAeadId(aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(variant.variant)
          .SetKemId(kem_id)
          .SetKdfId(kdf_id)
          .SetAeadId(aead_id)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(HpkeParametersTest, VariantNotEqual) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HpkeParametersTest, KemIdNotEqual) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HpkeParametersTest, KdfIdNotEqual) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HpkeParametersTest, AeadIdNotEqual) {
  util::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
