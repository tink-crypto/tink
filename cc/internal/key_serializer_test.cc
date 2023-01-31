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

#include "tink/internal/key_serializer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serializer_index.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/secret_key_access_token.h"
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

util::StatusOr<ExampleSerialization> Serialize(ExampleKey key,
                                               SecretKeyAccessToken token) {
  return ExampleSerialization();
}

TEST(KeyParserTest, Create) {
  KeySerializer<ExampleKey, ExampleSerialization> serializer(Serialize);

  EXPECT_THAT(serializer.Index(),
              Eq(SerializerIndex::Create<ExampleKey, ExampleSerialization>()));
}

TEST(KeyParserTest, SerializeKey) {
  KeySerializer<ExampleKey, ExampleSerialization> serializer(Serialize);

  util::StatusOr<ExampleSerialization> serialization =
      serializer.SerializeKey(ExampleKey(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT(serialization->ObjectIdentifier(), Eq("example_type_url"));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
