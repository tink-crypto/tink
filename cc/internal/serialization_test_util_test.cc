// Copyright 2023 Google LLC
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

#include "tink/internal/serialization_test_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;

TEST(SerializationTest, Create) {
  EXPECT_THAT(BaseSerialization("base_type_url").ObjectIdentifier(),
              Eq("base_type_url"));
  EXPECT_THAT(NoIdSerialization().ObjectIdentifier(), Eq(kNoIdTypeUrl));
  EXPECT_THAT(IdParamsSerialization().ObjectIdentifier(), Eq(kIdTypeUrl));

  IdKeySerialization id_key(123);
  EXPECT_THAT(id_key.ObjectIdentifier(), Eq(kIdTypeUrl));
  EXPECT_THAT(id_key.GetKeyId(), Eq(123));
}

TEST(NoIdParamsTest, Create) {
  NoIdParams params;

  EXPECT_THAT(params.HasIdRequirement(), IsFalse());
  EXPECT_THAT(params, Eq(NoIdParams()));
  EXPECT_THAT(params, Not(Eq(IdParams())));
}

TEST(NoIdParamsTest, ParseAndSerialize) {
  EXPECT_THAT(ParseNoIdParams(NoIdSerialization()), IsOkAndHolds(NoIdParams()));
  EXPECT_THAT(SerializeNoIdParams(NoIdParams()),
              IsOkAndHolds(NoIdSerialization()));
}

TEST(IdParamsTest, Create) {
  IdParams params;

  EXPECT_THAT(params.HasIdRequirement(), IsTrue());
  EXPECT_THAT(params, Eq(IdParams()));
  EXPECT_THAT(params, Not(Eq(NoIdParams())));
}

TEST(IdParamsTest, ParseAndSerialize) {
  EXPECT_THAT(ParseIdParams(IdParamsSerialization()), IsOkAndHolds(IdParams()));
  EXPECT_THAT(SerializeIdParams(IdParams()),
              IsOkAndHolds(IdParamsSerialization()));
}

TEST(NoIdKeyTest, Create) {
  NoIdKey key;

  EXPECT_THAT(key.GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(key.GetParameters(), Eq(NoIdParams()));
  EXPECT_THAT(key, Eq(NoIdKey()));
  EXPECT_THAT(key, Not(Eq(IdKey(123))));
}

TEST(NoIdKeyTest, ParseAndSerialize) {
  EXPECT_THAT(ParseNoIdKey(NoIdSerialization(), InsecureSecretKeyAccess::Get()),
              IsOkAndHolds(NoIdKey()));
  EXPECT_THAT(SerializeNoIdKey(NoIdKey(), InsecureSecretKeyAccess::Get()),
              IsOkAndHolds(NoIdSerialization()));
}

TEST(IdKeyTest, Create) {
  IdKey key(123);

  EXPECT_THAT(key.GetIdRequirement(), Eq(123));
  EXPECT_THAT(key.GetParameters(), Eq(IdParams()));
  EXPECT_THAT(key, Eq(IdKey(123)));
  EXPECT_THAT(key, Not(Eq(IdKey(456))));
  EXPECT_THAT(key, Not(Eq(NoIdKey())));
}

TEST(IdKeyTest, ParseAndSerialize) {
  EXPECT_THAT(ParseIdKey(IdKeySerialization(123),
                         InsecureSecretKeyAccess::Get()),
              IsOkAndHolds(IdKey(123)));
  EXPECT_THAT(SerializeIdKey(IdKey(123), InsecureSecretKeyAccess::Get()),
              IsOkAndHolds(IdKeySerialization(123)));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
