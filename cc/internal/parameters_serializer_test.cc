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

class ExampleParameters : public Parameters {
 public:
  bool HasIdRequirement() const override { return false; }

  bool operator==(const Parameters& other) const override { return true; }
};

class DifferentParameters : public Parameters {
 public:
  bool HasIdRequirement() const override { return false; }

  bool operator==(const Parameters& other) const override { return true; }
};

class ExampleSerialization : public Serialization {
 public:
  absl::string_view ObjectIdentifier() const override {
    return "example_type_url";
  }
};

util::StatusOr<ExampleSerialization> Serialize(ExampleParameters parameters) {
  return ExampleSerialization();
}

TEST(ParametersParserTest, Create) {
  ParametersSerializer<ExampleParameters, ExampleSerialization> serializer(
      "example_type_url", Serialize);

  EXPECT_THAT(serializer.ObjectIdentifier(), Eq("example_type_url"));
  EXPECT_THAT(
      serializer.Index(),
      Eq(SerializerIndex::Create<ExampleParameters, ExampleSerialization>()));
}

TEST(ParametersParserTest, SerializeParameters) {
  std::unique_ptr<ParametersSerializerBase> serializer = absl::make_unique<
      ParametersSerializer<ExampleParameters, ExampleSerialization>>(
      "example_type_url", Serialize);

  ExampleParameters parameters;
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      serializer->SerializeParameters(parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq("example_type_url"));
}

TEST(ParametersParserTest, SerializeParametersWithInvalidParametersType) {
  std::unique_ptr<ParametersSerializerBase> serializer = absl::make_unique<
      ParametersSerializer<ExampleParameters, ExampleSerialization>>(
      "example_type_url", Serialize);

  DifferentParameters parameters;
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      serializer->SerializeParameters(parameters);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
