// Copyright 2024 Google LLC
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

#include "tink/aead/aes_ctr_hmac_aead_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  int aes_key_size;
  int hmac_key_size;
  int iv_size;
  int tag_size;
  AesCtrHmacAeadParameters::HashType hash_type;
  AesCtrHmacAeadParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using AesCtrHmacAeadKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacAeadKeyBuildTestSuite, AesCtrHmacAeadKeyTest,
    Values(TestCase{/*aes_key_size=*/16, /*hmac_key_size=*/16,
                    /*iv_size=*/12, /*tag_size=*/28,
                    AesCtrHmacAeadParameters::HashType::kSha256,
                    AesCtrHmacAeadParameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{/*aes_key_size=*/24, /*hmac_key_size=*/32,
                    /*iv_size=*/16, /*tag_size=*/32,
                    AesCtrHmacAeadParameters::HashType::kSha384,
                    AesCtrHmacAeadParameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{/*aes_key_size=*/32, /*hmac_key_size=*/16,
                    /*iv_size=*/16, /*tag_size=*/48,
                    AesCtrHmacAeadParameters::HashType::kSha512,
                    AesCtrHmacAeadParameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt, ""}));

TEST_P(AesCtrHmacAeadKeyTest, BuildKeySucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(test_case.aes_key_size);
  RestrictedData hmac_secret = RestrictedData(test_case.hmac_key_size);

  util::StatusOr<AesCtrHmacAeadKey> key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(test_case.id_requirement)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(key->GetAesKeyBytes(GetPartialKeyAccess()), Eq(aes_secret));
  EXPECT_THAT(key->GetHmacKeyBytes(GetPartialKeyAccess()), Eq(hmac_secret));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithMismatchedAesKeySizeFails) {
  // AES key size parameter is 32 bytes.
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // AES key material size is 16 bytes (also a valid key length).
  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/16);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetAesKeyBytes(aes_secret)
                  .SetHmacKeyBytes(hmac_secret)
                  .SetIdRequirement(123)
                  .Build(GetPartialKeyAccess())
                  .status(),
                  StatusIs(absl::StatusCode::kInvalidArgument,
                           HasSubstr("AES key size does not match")));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithoutSettingAParametersFails) {
  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(
      AesCtrHmacAeadKey::Builder()
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess())
          .status(),
          StatusIs(absl::StatusCode::kInvalidArgument,
                   HasSubstr("Cannot build without setting the parameters")));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithoutSettingAesKeySizeFails) {
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetHmacKeyBytes(hmac_secret)
                  .SetIdRequirement(123)
                  .Build(GetPartialKeyAccess())
                  .status(),
                  StatusIs(absl::StatusCode::kInvalidArgument,
                           HasSubstr("Cannot build without AES key material")));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithoutSettingHmacKeySizeFails) {
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess())
          .status(),
          StatusIs(absl::StatusCode::kInvalidArgument,
                   HasSubstr("Cannot build without HMAC key material")));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithMismatchedHmacKeySizeFails) {
  // HMAC key size parameter is 32 bytes.
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // HMAC key material size is 16 bytes (also a valid key length).
  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetAesKeyBytes(aes_secret)
                  .SetHmacKeyBytes(hmac_secret)
                  .SetIdRequirement(123)
                  .Build(GetPartialKeyAccess())
                  .status(),
                  StatusIs(absl::StatusCode::kInvalidArgument,
                           HasSubstr("HMAC key size does not match")));
}

TEST(AesCtrHmacAeadKeyTest, BuildNoPrefixKeyWithIdRequirementFails) {
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess())
          .status(),
          StatusIs(absl::StatusCode::kInvalidArgument,
                   HasSubstr("Cannot create key with ID requirement with "
                             "parameters without ID requirement")));
}

TEST(AesCtrHmacAeadKeyTest, BuildTinkKeyWithoutIdRequirementFails) {
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetAesKeyBytes(aes_secret)
                  .SetHmacKeyBytes(hmac_secret)
                  .Build(GetPartialKeyAccess())
                  .status(),
                  StatusIs(absl::StatusCode::kInvalidArgument,
                           HasSubstr("Cannot create key without ID requirement "
                                     "with parameters with ID requirement")));
}

TEST_P(AesCtrHmacAeadKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(test_case.aes_key_size);
  RestrictedData hmac_secret = RestrictedData(test_case.hmac_key_size);

  util::StatusOr<AesCtrHmacAeadKey> key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(test_case.id_requirement)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesCtrHmacAeadKey> other_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(test_case.id_requirement)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesCtrHmacAeadKeyTest, DifferentParametersKeysNotEqual) {
  util::StatusOr<AesCtrHmacAeadParameters> tink_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  util::StatusOr<AesCtrHmacAeadParameters> crunchy_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<AesCtrHmacAeadKey> tink_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*tink_parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(0x01020304)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(tink_key, IsOk());

  util::StatusOr<AesCtrHmacAeadKey> crunchy_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*crunchy_parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(0x01020304)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(crunchy_key, IsOk());

  EXPECT_TRUE(*tink_key != *crunchy_key);
  EXPECT_TRUE(*crunchy_key != *tink_key);
  EXPECT_FALSE(*tink_key == *crunchy_key);
  EXPECT_FALSE(*crunchy_key == *tink_key);
}

TEST(AesCtrHmacAeadKeyTest, DifferentAesKeyMaterialNotEqual) {
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData aes_secret2 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<AesCtrHmacAeadKey> key = AesCtrHmacAeadKey::Builder()
                                              .SetParameters(*parameters)
                                              .SetAesKeyBytes(aes_secret1)
                                              .SetHmacKeyBytes(hmac_secret)
                                              .SetIdRequirement(0x01020304)
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesCtrHmacAeadKey> other_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret2)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(0x01020304)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCtrHmacAeadKeyTest, DifferentHmacKeyMaterialNotEqual) {
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret2 = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<AesCtrHmacAeadKey> key = AesCtrHmacAeadKey::Builder()
                                              .SetParameters(*parameters)
                                              .SetAesKeyBytes(aes_secret)
                                              .SetHmacKeyBytes(hmac_secret1)
                                              .SetIdRequirement(0x01020304)
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesCtrHmacAeadKey> other_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret2)
          .SetIdRequirement(0x01020304)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCtrHmacAeadKeyTest, DifferentIdRequirementKeysNotEqual) {
  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  util::StatusOr<AesCtrHmacAeadKey> key = AesCtrHmacAeadKey::Builder()
                                              .SetParameters(*parameters)
                                              .SetAesKeyBytes(aes_secret)
                                              .SetHmacKeyBytes(hmac_secret)
                                              .SetIdRequirement(0x01020304)
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesCtrHmacAeadKey> other_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(0x02030405)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
