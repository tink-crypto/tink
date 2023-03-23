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

#include "tink/internal/serializer_index.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/internal/serialization_test_util.h"

namespace crypto {
namespace tink {
namespace internal {

using ::testing::Eq;
using ::testing::Not;

TEST(SerializerIndex, CreateEquivalentFromParameters) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT((SerializerIndex::Create<NoIdParams, NoIdSerialization>()),
              Eq((SerializerIndex::Create<NoIdParams, NoIdSerialization>())));
  ASSERT_THAT((SerializerIndex::Create<NoIdParams, NoIdSerialization>()),
              Eq((SerializerIndex::Create<NoIdSerialization>(NoIdParams()))));
  ASSERT_THAT((SerializerIndex::Create<NoIdSerialization>(NoIdParams())),
              Eq((SerializerIndex::Create<NoIdSerialization>(NoIdParams()))));
}

TEST(SerializerIndex, CreateFromDifferentParametersType) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<NoIdParams, NoIdSerialization>()),
      Not(Eq((SerializerIndex::Create<IdParams, NoIdSerialization>()))));
  ASSERT_THAT(
      (SerializerIndex::Create<NoIdSerialization>(NoIdParams())),
      Not(Eq((SerializerIndex::Create<NoIdSerialization>(IdParams())))));
}

TEST(SerializerIndex, CreateFromSameParametersTypeWithDifferentSerialization) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<NoIdParams, NoIdSerialization>()),
      Not(Eq((SerializerIndex::Create<NoIdParams, IdParamsSerialization>()))));
  ASSERT_THAT(
      (SerializerIndex::Create<NoIdSerialization>(NoIdParams())),
      Not(Eq((SerializerIndex::Create<IdParamsSerialization>(NoIdParams())))));
}

TEST(SerializerIndex, CreateEquivalentFromKey) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT((SerializerIndex::Create<NoIdKey, NoIdSerialization>()),
              Eq((SerializerIndex::Create<NoIdKey, NoIdSerialization>())));
  ASSERT_THAT((SerializerIndex::Create<NoIdKey, NoIdSerialization>()),
              Eq((SerializerIndex::Create<NoIdSerialization>(NoIdKey()))));
  ASSERT_THAT((SerializerIndex::Create<NoIdSerialization>(NoIdKey())),
              Eq((SerializerIndex::Create<NoIdSerialization>(NoIdKey()))));
}

TEST(SerializerIndex, CreateFromDifferentKeyType) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT((SerializerIndex::Create<NoIdKey, NoIdSerialization>()),
              Not(Eq((SerializerIndex::Create<IdKey, NoIdSerialization>()))));
  ASSERT_THAT(
      (SerializerIndex::Create<NoIdSerialization>(NoIdKey())),
      Not(Eq((SerializerIndex::Create<NoIdSerialization>(IdKey(/*id=*/1))))));
}

TEST(SerializerIndex, CreateFromSameKeyTypeWithDifferentSerialization) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<NoIdKey, NoIdSerialization>()),
      Not(Eq((SerializerIndex::Create<NoIdKey, IdKeySerialization>()))));
  ASSERT_THAT(
      (SerializerIndex::Create<NoIdSerialization>(NoIdKey())),
      Not(Eq((SerializerIndex::Create<IdKeySerialization>(NoIdKey())))));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
