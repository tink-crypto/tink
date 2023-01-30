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

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace internal {

using ::testing::Eq;
using ::testing::Not;

class ExampleSerialization : public Serialization {
 public:
  explicit ExampleSerialization(absl::string_view object_identifier)
      : object_identifier_(object_identifier) {}

  absl::string_view ObjectIdentifier() const override {
    return object_identifier_;
  }

 protected:
  std::string object_identifier_;
};

class DifferentSerialization : public ExampleSerialization {
 public:
  explicit DifferentSerialization(absl::string_view object_identifier)
      : ExampleSerialization(object_identifier) {}
};

class ExampleParameters : public Parameters {
 public:
  bool HasIdRequirement() const override { return false; }

  bool operator==(const Parameters& other) const override { return true; }
};

class DifferentParameters : public ExampleParameters {};

class ExampleKey : public Key {
 public:
  const Parameters& GetParameters() const override { return parameters_; }

  absl::optional<int> GetIdRequirement() const override { return 123; }

  bool operator==(const Key& other) const override { return true; }

 private:
  ExampleParameters parameters_;
};

class DifferentKey : public ExampleKey {};

TEST(SerializerIndex, CreateEquivalentFromParameters) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleParameters, ExampleSerialization>()),
      Eq((SerializerIndex::Create<ExampleParameters, ExampleSerialization>())));
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleParameters, ExampleSerialization>()),
      Eq((SerializerIndex::Create<ExampleSerialization>(ExampleParameters()))));
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleSerialization>(ExampleParameters())),
      Eq((SerializerIndex::Create<ExampleSerialization>(ExampleParameters()))));
}

TEST(SerializerIndex, CreateFromDifferentParametersType) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleParameters, ExampleSerialization>()),
      Not(Eq((SerializerIndex::Create<DifferentParameters,
                                      ExampleSerialization>()))));
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleSerialization>(ExampleParameters())),
      Not(Eq((SerializerIndex::Create<ExampleSerialization>(
          DifferentParameters())))));
}

TEST(SerializerIndex, CreateFromSameParametersTypeWithDifferentSerialization) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleParameters, ExampleSerialization>()),
      Not(Eq((SerializerIndex::Create<ExampleParameters,
                                      DifferentSerialization>()))));
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleSerialization>(ExampleParameters())),
      Not(Eq((SerializerIndex::Create<DifferentSerialization>(
          ExampleParameters())))));
}

TEST(SerializerIndex, CreateEquivalentFromKey) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleKey, ExampleSerialization>()),
      Eq((SerializerIndex::Create<ExampleKey, ExampleSerialization>())));
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleKey, ExampleSerialization>()),
      Eq((SerializerIndex::Create<ExampleSerialization>(ExampleKey()))));
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleSerialization>(ExampleKey())),
      Eq((SerializerIndex::Create<ExampleSerialization>(ExampleKey()))));
}

TEST(SerializerIndex, CreateFromDifferentKeyType) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleKey, ExampleSerialization>()),
      Not(Eq((SerializerIndex::Create<DifferentKey, ExampleSerialization>()))));
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleSerialization>(ExampleKey())),
      Not(Eq((SerializerIndex::Create<ExampleSerialization>(DifferentKey())))));
}

TEST(SerializerIndex, CreateFromSameKeyTypeWithDifferentSerialization) {
  // Multi-parameter templates require extra surrounding parentheses.
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleKey, ExampleSerialization>()),
      Not(Eq((SerializerIndex::Create<ExampleKey, DifferentSerialization>()))));
  ASSERT_THAT(
      (SerializerIndex::Create<ExampleSerialization>(ExampleKey())),
      Not(Eq((SerializerIndex::Create<DifferentSerialization>(ExampleKey())))));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
