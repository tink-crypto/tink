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

#include "tink/internal/parameters_parser.h"

#include <memory>
#include <string_view>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/internal/parser_index.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_test_util.h"
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
using ::testing::IsFalse;

TEST(ParametersParserTest, Create) {
  std::unique_ptr<ParametersParser> parser =
      absl::make_unique<ParametersParserImpl<NoIdSerialization, NoIdParams>>(
          kNoIdTypeUrl, ParseNoIdParams);

  EXPECT_THAT(parser->ObjectIdentifier(), Eq(kNoIdTypeUrl));
  EXPECT_THAT(parser->Index(),
              Eq(ParserIndex::Create<NoIdSerialization>(kNoIdTypeUrl)));
}

TEST(ParametersParserTest, ParseParameters) {
  std::unique_ptr<ParametersParser> parser =
      absl::make_unique<ParametersParserImpl<NoIdSerialization, NoIdParams>>(
          kNoIdTypeUrl, ParseNoIdParams);

  NoIdSerialization serialization;
  util::StatusOr<std::unique_ptr<Parameters>> params =
      parser->ParseParameters(serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsFalse());
}

TEST(ParametersParserTest, ParseParametersWithInvalidSerializationType) {
  std::unique_ptr<ParametersParser> parser =
      absl::make_unique<ParametersParserImpl<NoIdSerialization, NoIdParams>>(
          kNoIdTypeUrl, ParseNoIdParams);

  IdParamsSerialization serialization;
  util::StatusOr<std::unique_ptr<Parameters>> params =
      parser->ParseParameters(serialization);
  ASSERT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ParametersParserTest, ParseParametersWithInvalidObjectIdentifier) {
  std::unique_ptr<ParametersParser> parser =
      absl::make_unique<ParametersParserImpl<NoIdSerialization, NoIdParams>>(
          "mismatched_type_url", ParseNoIdParams);

  IdParamsSerialization serialization;
  util::StatusOr<std::unique_ptr<Parameters>> params =
      parser->ParseParameters(serialization);
  ASSERT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
