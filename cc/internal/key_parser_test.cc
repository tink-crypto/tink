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

#include "tink/internal/key_parser.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/parser_index.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;

class ExampleParameters : public Parameters {
 public:
  bool HasIdRequirement() const override { return false; }

  bool operator==(const Parameters& other) const override { return true; }
};

class ExampleKey : public Key {
 public:
  const Parameters& GetParameters() const override { return parameters_; }

  absl::optional<int> GetIdRequirement() const override { return 123; }

  bool operator==(const Key& other) const override { return true; }

 private:
  ExampleParameters parameters_;
};

class ExampleSerialization : public Serialization {
 public:
  absl::string_view ObjectIdentifier() const override {
    return "example_type_url";
  }
};

util::StatusOr<ExampleKey> Parse(ExampleSerialization serialization,
                                 SecretKeyAccessToken token) {
  return ExampleKey();
}

TEST(KeyParserTest, Create) {
  KeyParser<ExampleSerialization, ExampleKey> parser("example_type_url", Parse);

  EXPECT_THAT(parser.ObjectIdentifier(), Eq("example_type_url"));
  EXPECT_THAT(
      parser.Index(),
      Eq(ParserIndex::Create<ExampleSerialization>("example_type_url")));
}

TEST(KeyParserTest, ParseKey) {
  KeyParser<ExampleSerialization, ExampleKey> parser("example_type_url", Parse);

  util::StatusOr<ExampleKey> key =
      parser.ParseKey(ExampleSerialization(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetIdRequirement(), Eq(123));
  EXPECT_THAT(key->GetParameters(), Eq(ExampleParameters()));
  EXPECT_THAT(*key, Eq(ExampleKey()));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
