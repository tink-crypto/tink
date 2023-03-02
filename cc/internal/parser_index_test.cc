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

#include "tink/internal/parser_index.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "tink/internal/serialization.h"

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

TEST(ParserIndex, CreateEquivalent) {
  ASSERT_THAT(ParserIndex::Create<ExampleSerialization>("id"),
              Eq(ParserIndex::Create<ExampleSerialization>("id")));
  ASSERT_THAT(ParserIndex::Create<ExampleSerialization>("id"),
              Eq(ParserIndex::Create(ExampleSerialization("id"))));
  ASSERT_THAT(ParserIndex::Create(ExampleSerialization("id")),
              Eq(ParserIndex::Create(ExampleSerialization("id"))));
}

TEST(ParserIndex, CreateWithDifferentObjectIdentifier) {
  ASSERT_THAT(
      ParserIndex::Create<ExampleSerialization>("id"),
      Not(Eq(ParserIndex::Create<ExampleSerialization>("different id"))));
  ASSERT_THAT(
      ParserIndex::Create(ExampleSerialization("id")),
      Not(Eq(ParserIndex::Create(ExampleSerialization("different id")))));
}

TEST(ParserIndex, CreateWithDifferentSerializationType) {
  ASSERT_THAT(ParserIndex::Create<ExampleSerialization>("id"),
              Not(Eq(ParserIndex::Create<DifferentSerialization>("id"))));
  ASSERT_THAT(ParserIndex::Create(ExampleSerialization("id")),
              Not(Eq(ParserIndex::Create(DifferentSerialization("id")))));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
