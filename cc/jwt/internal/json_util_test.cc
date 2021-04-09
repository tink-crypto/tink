// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/internal/json_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;

namespace crypto {
namespace tink {
namespace jwt_internal {

TEST(JsonUtil, ParseThenSerializeStructWtihStringListOk) {
  auto proto_or =
      JsonStringToProtoStruct(R"({"some_key":["hello","world","!"]})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();

  ASSERT_THAT(ProtoStructToJsonString(proto),
              IsOkAndHolds(R"({"some_key":["hello","world","!"]})"));
}

TEST(JsonUtil, ParseThenSerializeStructWtihNumberOk) {
  auto proto_or = JsonStringToProtoStruct(R"({"some_key":-12345})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();

  ASSERT_THAT(ProtoStructToJsonString(proto),
              IsOkAndHolds(R"({"some_key":-12345})"));
}

TEST(JsonUtil, ParseThenSerializeStructWtihBoolOk) {
  auto proto_or = JsonStringToProtoStruct(R"({"some_key":false})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();

  ASSERT_THAT(ProtoStructToJsonString(proto),
              IsOkAndHolds(R"({"some_key":false})"));
}

TEST(JsonUtil, ParseThenSerializeListOk) {
  auto proto_or =
      JsonStringToProtoList(R"(["hello", "world", 42, true])");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::ListValue proto = proto_or.ValueOrDie();

  ASSERT_THAT(ProtoListToJsonString(proto),
              IsOkAndHolds(R"(["hello","world",42,true])"));
}

TEST(JsonUtil, ParseInvalidStructTokenNotOk) {
  auto proto_or = JsonStringToProtoStruct(R"({"some_key":false)");
  ASSERT_FALSE(proto_or.ok());
}

TEST(JsonUtil, ParseInvalidListTokenNotOk) {
  auto proto_or = JsonStringToProtoStruct(R"(["one", )");
  ASSERT_FALSE(proto_or.ok());
}

TEST(JsonUtil, ParseStructWithoutQuotesOk) {
  // TODO(b/360366279) Make parsing stricter that this is not allowed.
  auto proto_or = JsonStringToProtoStruct(R"({some_key:false})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();
  ASSERT_THAT(ProtoStructToJsonString(proto),
              IsOkAndHolds(R"({"some_key":false})"));
}

TEST(JsonUtil, ParseListWithoutQuotesNotOk) {
  auto proto_or = JsonStringToProtoList(R"([one,two])");
  EXPECT_FALSE(proto_or.ok());
}

TEST(JsonUtil, ParseStructWithCommentNotOk) {
  auto proto_or =
      JsonStringToProtoStruct(R"({"some_key":false /* comment */})");
  EXPECT_FALSE(proto_or.ok());
}

TEST(JsonUtil, ParseListWithCommentNotOk) {
  auto proto_or =
      JsonStringToProtoList(R"(["hello", "world" /* comment */])");
  EXPECT_FALSE(proto_or.ok());
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
