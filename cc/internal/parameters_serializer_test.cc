// Copyright 2022 Google LLC
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

#include "tink/internal/parameters_serializer.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_test_util.h"
#include "tink/internal/serializer_index.h"
#include "tink/parameters.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;

TEST(ParametersSerializerTest, Create) {
  std::unique_ptr<ParametersSerializer> serializer = absl::make_unique<
      ParametersSerializerImpl<NoIdParams, NoIdSerialization>>(
      kNoIdTypeUrl, SerializeNoIdParams);

  EXPECT_THAT(serializer->ObjectIdentifier(), Eq(kNoIdTypeUrl));
  EXPECT_THAT(serializer->Index(),
              Eq(SerializerIndex::Create<NoIdParams, NoIdSerialization>()));
}

TEST(ParametersSerializerTest, SerializeParameters) {
  std::unique_ptr<ParametersSerializer> serializer = absl::make_unique<
      ParametersSerializerImpl<NoIdParams, NoIdSerialization>>(
      kNoIdTypeUrl, SerializeNoIdParams);

  NoIdParams parameters;
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      serializer->SerializeParameters(parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(ParametersSerializerTest, SerializeParametersWithInvalidParametersType) {
  std::unique_ptr<ParametersSerializer> serializer = absl::make_unique<
      ParametersSerializerImpl<NoIdParams, NoIdSerialization>>(
      kNoIdTypeUrl, SerializeNoIdParams);

  IdParams parameters;
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      serializer->SerializeParameters(parameters);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
