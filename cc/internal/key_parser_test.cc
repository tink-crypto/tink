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

#include <memory>
#include <string_view>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/parser_index.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_test_util.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;

TEST(KeyParserTest, Create) {
  std::unique_ptr<KeyParser> parser =
      absl::make_unique<KeyParserImpl<NoIdSerialization, NoIdKey>>(
          kNoIdTypeUrl, ParseNoIdKey);

  EXPECT_THAT(parser->ObjectIdentifier(), Eq(kNoIdTypeUrl));
  EXPECT_THAT(
      parser->Index(),
      Eq(ParserIndex::Create<NoIdSerialization>(kNoIdTypeUrl)));
}

TEST(KeyParserTest, ParseKey) {
  std::unique_ptr<KeyParser> parser =
      absl::make_unique<KeyParserImpl<NoIdSerialization, NoIdKey>>(
          kNoIdTypeUrl, ParseNoIdKey);

  NoIdSerialization serialization;
  util::StatusOr<std::unique_ptr<Key>> key =
      parser->ParseKey(serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT((*key)->GetParameters(), Eq(NoIdParams()));
  EXPECT_THAT(**key, Eq(NoIdKey()));
}

TEST(KeyParserTest, ParseKeyWithInvalidSerializationType) {
  std::unique_ptr<KeyParser> parser =
      absl::make_unique<KeyParserImpl<NoIdSerialization, NoIdKey>>(
          "example_type_url", ParseNoIdKey);

  IdKeySerialization serialization(/*id=*/123);
  util::StatusOr<std::unique_ptr<Key>> key =
      parser->ParseKey(serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KeyParserTest, ParseKeyWithInvalidObjectIdentifier) {
  std::unique_ptr<KeyParser> parser =
      absl::make_unique<KeyParserImpl<NoIdSerialization, NoIdKey>>(
          "mismatched_type_url", ParseNoIdKey);

  NoIdSerialization serialization;
  util::StatusOr<std::unique_ptr<Key>> key =
      parser->ParseKey(serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
