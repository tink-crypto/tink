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
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/json_object.h"

#include "gtest/gtest.h"
#include "tink/jwt/json_struct_util.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;

namespace crypto {
namespace tink {

TEST(JsonObject, KeyStringValueOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = "some string";

  auto json = JsonObject(proto);
  ASSERT_THAT(json.SetValueAsString("other_key", "other string"), IsOk());

  ASSERT_THAT(json.GetValueAsString("some_key"), IsOkAndHolds("some string"));
  ASSERT_THAT(json.GetValueAsString("other_key"), IsOkAndHolds("other string"));
}

TEST(JsonObject, KeyStringValueNotFound) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = "some string";

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsString("wrong_key").status(),
              StatusIs(util::error::NOT_FOUND));
}

TEST(JsonObject, KeyStringValueInvalid) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = "some string";

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsTime("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsBool("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsNumber("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsStringList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsNumberList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, KeyBoolValueOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = false;

  auto json = JsonObject(proto);
  ASSERT_THAT(json.SetValueAsBool("other_key", true), IsOk());

  ASSERT_THAT(json.GetValueAsBool("some_key"), IsOkAndHolds(false));
  ASSERT_THAT(json.GetValueAsBool("other_key"), IsOkAndHolds(true));
}

TEST(JsonObject, KeyBoolValueNotFound) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = true;

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsBool("wrong_key").status(),
              StatusIs(util::error::NOT_FOUND));
}

TEST(JsonObject, KeyBoolValueInvalid) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = false;

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsTime("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsNumber("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsStringList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsNumberList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, KeyStringListValueOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"].append("value1");
  proto_builder["some_key"].append("value2");
  proto_builder["some_key"].append("value3");

  auto json = JsonObject(proto);
  ASSERT_THAT(json.AppendValueToStringList("some_key", "value4"), IsOk());

  std::vector<absl::string_view> list = {"value3", "value2", "value1"};
  for (auto& v : list) {
    ASSERT_THAT(json.AppendValueToStringList("other_key", v), IsOk());
  }
  ASSERT_THAT(json.AppendValueToStringList("other_key", "value0"), IsOk());

  std::vector<std::string> list2 = {"value1", "value2", "value3", "value4"};
  ASSERT_THAT(json.GetValueAsStringList("some_key"), IsOkAndHolds(list2));
  list2 = {"value3", "value2", "value1", "value0"};
  ASSERT_THAT(json.GetValueAsStringList("other_key"), IsOkAndHolds(list2));
}

TEST(JsonObject, KeyStringListFieldNamesAndTypesOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"].append("value1");
  proto_builder["some_key"].append("value2");
  proto_builder["some_key"].append("value3");
  auto json = JsonObject(proto);

  util::StatusOr<absl::flat_hash_map<std::string, enum JsonFieldType>>
      fields_or = json.getFieldNamesAndTypes();
  ASSERT_THAT(fields_or.status(), IsOk());
  auto fields = fields_or.ValueOrDie();
  ASSERT_EQ(fields.size(), 1);
  ASSERT_EQ(fields.count("some_key"), 1);
  ASSERT_EQ(fields.at("some_key"), JsonFieldType::kStringList);
}

TEST(JsonObject, KeyNumberListFieldNamesAndTypesOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"].append(1);
  proto_builder["some_key"].append(2);
  proto_builder["some_key"].append(3);
  auto json = JsonObject(proto);

  util::StatusOr<absl::flat_hash_map<std::string, enum JsonFieldType>>
      fields_or = json.getFieldNamesAndTypes();
  ASSERT_THAT(fields_or.status(), IsOk());
  auto fields = fields_or.ValueOrDie();
  ASSERT_EQ(fields.size(), 1);
  ASSERT_EQ(fields.count("some_key"), 1);
  ASSERT_EQ(fields.at("some_key"), JsonFieldType::kNumberList);
}

TEST(JsonObject, KeyNumberFieldNamesAndTypesOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = 123;
  auto json = JsonObject(proto);

  util::StatusOr<absl::flat_hash_map<std::string, enum JsonFieldType>>
      fields_or = json.getFieldNamesAndTypes();
  ASSERT_THAT(fields_or.status(), IsOk());
  auto fields = fields_or.ValueOrDie();
  ASSERT_EQ(fields.size(), 1);
  ASSERT_EQ(fields.count("some_key"), 1);
  ASSERT_EQ(fields.at("some_key"), JsonFieldType::kNumber);
}

TEST(JsonObject, KeyStringFieldNamesAndTypesOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = "bla";
  auto json = JsonObject(proto);

  util::StatusOr<absl::flat_hash_map<std::string, enum JsonFieldType>>
      fields_or = json.getFieldNamesAndTypes();
  ASSERT_THAT(fields_or.status(), IsOk());
  auto fields = fields_or.ValueOrDie();
  ASSERT_EQ(fields.size(), 1);
  ASSERT_EQ(fields.count("some_key"), 1);
  ASSERT_EQ(fields.at("some_key"), JsonFieldType::kString);
}

TEST(JsonObject, KeyBoolFieldNamesAndTypesOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = false;
  auto json = JsonObject(proto);

  util::StatusOr<absl::flat_hash_map<std::string, enum JsonFieldType>>
      fields_or = json.getFieldNamesAndTypes();
  ASSERT_THAT(fields_or.status(), IsOk());
  auto fields = fields_or.ValueOrDie();
  ASSERT_EQ(fields.size(), 1);
  ASSERT_EQ(fields.count("some_key"), 1);
  ASSERT_EQ(fields.at("some_key"), JsonFieldType::kBool);
}

TEST(JsonObject, EmptyStringToListInvalidArgument) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = "";

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsStringList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, EmptyListOk) {
  std::vector<std::string> emptyList;

  auto proto_or = JsonStructBuilder::FromString(R"({"some_key": []})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();

  auto json = JsonObject(proto);

  ASSERT_THAT(json.GetValueAsStringList("some_key"), IsOkAndHolds(emptyList));
}

TEST(JsonObject, ParseThenSerializeNumberListOk) {
  auto proto_or = JsonStructBuilder::FromString(R"({"some_key":[1,2,3]})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();

  ASSERT_THAT(JsonStructBuilder::ToString(proto),
              IsOkAndHolds(R"({"some_key":[1,2,3]})"));

  auto json = JsonObject(proto);
  ASSERT_THAT(json.ToString(), IsOkAndHolds(R"({"some_key":[1,2,3]})"));
}

TEST(JsonObject, ParseThenSerializeStringListOk) {
  auto proto_or =
      JsonStructBuilder::FromString(R"({"some_key":["hello","world","!"]})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();

  ASSERT_THAT(JsonStructBuilder::ToString(proto),
              IsOkAndHolds(R"({"some_key":["hello","world","!"]})"));

  auto json = JsonObject(proto);
  ASSERT_THAT(json.ToString(),
              IsOkAndHolds(R"({"some_key":["hello","world","!"]})"));
}

TEST(JsonObject, ParseThenSerializeNumberOk) {
  auto proto_or = JsonStructBuilder::FromString(R"({"some_key":-12345})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();

  ASSERT_THAT(JsonStructBuilder::ToString(proto),
              IsOkAndHolds(R"({"some_key":-12345})"));

  auto json = JsonObject(proto);
  ASSERT_THAT(json.ToString(), IsOkAndHolds(R"({"some_key":-12345})"));
}

TEST(JsonObject, ParseThenSerializeBoolOk) {
  auto proto_or = JsonStructBuilder::FromString(R"({"some_key":false})");
  ASSERT_THAT(proto_or.status(), IsOk());
  google::protobuf::Struct proto = proto_or.ValueOrDie();

  ASSERT_THAT(JsonStructBuilder::ToString(proto),
              IsOkAndHolds(R"({"some_key":false})"));
}

TEST(JsonObject, BuildThenSerializeNumberListOk) {
  auto json = JsonObject();
  ASSERT_THAT(json.AppendValueToNumberList("some_key", 1), IsOk());
  ASSERT_THAT(json.AppendValueToNumberList("some_key", 2), IsOk());
  ASSERT_THAT(json.AppendValueToNumberList("some_key", 3), IsOk());

  ASSERT_THAT(json.ToString(), IsOkAndHolds(R"({"some_key":[1,2,3]})"));
}

TEST(JsonObject, BuildThenSerializeStringListOk) {
  auto json = JsonObject();
  ASSERT_THAT(json.AppendValueToStringList("some_key", "hello"), IsOk());
  ASSERT_THAT(json.AppendValueToStringList("some_key", "world"), IsOk());
  ASSERT_THAT(json.AppendValueToStringList("some_key", "!"), IsOk());

  ASSERT_THAT(json.ToString(),
              IsOkAndHolds(R"({"some_key":["hello","world","!"]})"));
}

TEST(JsonObject, BuildThenSerializeNumberOk) {
  auto json = JsonObject();
  ASSERT_THAT(json.SetValueAsNumber("some_key", -4567), IsOk());

  ASSERT_THAT(json.ToString(), IsOkAndHolds(R"({"some_key":-4567})"));
}

TEST(JsonObject, BuildThenSerializeBoolOk) {
  auto json = JsonObject();
  ASSERT_THAT(json.SetValueAsBool("some_key", true), IsOk());

  ASSERT_THAT(json.ToString(), IsOkAndHolds(R"({"some_key":true})"));
}

TEST(JsonObject, KeyStringListValueNotFound) {
  auto json = JsonObject();
  std::vector<absl::string_view> list = {"value1", "value2", "value3"};
  for (auto& v : list) {
    ASSERT_THAT(json.AppendValueToStringList("some_key", v), IsOk());
  }

  ASSERT_THAT(json.GetValueAsStringList("wrong_key").status(),
              StatusIs(util::error::NOT_FOUND));
}

TEST(JsonObject, KeyStringListValueInvalid) {
  auto json = JsonObject();
  std::vector<absl::string_view> list = {"value1", "value2", "value3"};
  for (auto& v : list) {
    ASSERT_THAT(json.AppendValueToStringList("some_key", v), IsOk());
  }

  ASSERT_THAT(json.GetValueAsTime("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsNumber("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsBool("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsNumberList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, KeyNumberListValueOk) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"].append(1);
  proto_builder["some_key"].append(2);
  proto_builder["some_key"].append(3);

  auto json = JsonObject(proto);
  std::vector<int> list = {3, 2, 1};
  for (auto& v : list) {
    ASSERT_THAT(json.AppendValueToNumberList("other_key", v), IsOk());
  }

  list = {1, 2, 3};
  ASSERT_THAT(json.GetValueAsNumberList("some_key"), IsOkAndHolds(list));
  list = {3, 2, 1};
  ASSERT_THAT(json.GetValueAsNumberList("other_key"), IsOkAndHolds(list));
}

TEST(JsonObject, KeyNumberListValueNotFound) {
  auto json = JsonObject();
  std::vector<int> list = {1, 2, 3};
  for (auto& v : list) {
    ASSERT_THAT(json.AppendValueToNumberList("some_key", v), IsOk());
  }

  ASSERT_THAT(json.GetValueAsNumberList("wrong_key").status(),
              StatusIs(util::error::NOT_FOUND));
}

TEST(JsonObject, KeyNumberListValueInvalid) {
  auto json = JsonObject();
  std::vector<int> list = {1, 2, 3};
  for (auto& v : list) {
    ASSERT_THAT(json.AppendValueToNumberList("some_key", v), IsOk());
  }

  ASSERT_THAT(json.GetValueAsTime("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsNumber("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsBool("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsStringList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, KeyTimeValueOk) {
  absl::Time now = absl::Now();
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = static_cast<int>(absl::ToUnixSeconds(now));

  auto json = JsonObject(proto);
  ASSERT_THAT(json.SetValueAsTime("other_key", now + absl::Minutes(1)), IsOk());

  auto key_or = json.GetValueAsTime("some_key");
  ASSERT_THAT(key_or.status(), IsOk());
  auto value = key_or.ValueOrDie();
  ASSERT_LT(value, now + absl::Seconds(1));
  ASSERT_GT(value, now - absl::Seconds(1));

  key_or = json.GetValueAsTime("other_key");
  ASSERT_THAT(key_or.status(), IsOk());
  value = key_or.ValueOrDie();
  ASSERT_LT(value, now + absl::Minutes(1) + absl::Seconds(1));
  ASSERT_GT(value, now + absl::Minutes(1) - absl::Seconds(1));
}

TEST(JsonObject, KeyTimeValueNotFound) {
  absl::Time now = absl::Now();
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = static_cast<int>(absl::ToUnixSeconds(now));

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsTime("wrong_key").status(),
              StatusIs(util::error::NOT_FOUND));
}

TEST(JsonObject, KeyTimeValueInvalid) {
  absl::Time now = absl::Now();
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  proto_builder["some_key"] = static_cast<int>(absl::ToUnixSeconds(now));

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsBool("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsStringList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
  ASSERT_THAT(json.GetValueAsNumberList("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, KeyStringThenNumberOverwriteOK) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);

  // String then number using protobuf builder.
  proto_builder["some_key"] = "hello";
  proto_builder["some_key"] = 123456;

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsNumber("some_key"), IsOkAndHolds(123456));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));

  // String then number using protobuf builder then Json setter.
  proto_builder["some_key"] = "hello";

  json = JsonObject(proto);
  ASSERT_THAT(json.SetValueAsNumber("some_key", 123456), IsOk());
  ASSERT_THAT(json.GetValueAsNumber("some_key"), IsOkAndHolds(123456));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, KeyNumberThenStringOverwriteOK) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  // Number then string using protobuf builder.
  proto_builder["some_key"] = 123456;
  proto_builder["some_key"] = "hello";

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsString("some_key"), IsOkAndHolds("hello"));
  ASSERT_THAT(json.GetValueAsNumber("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));

  // Number then string using protobuf builder then Json setter.
  proto_builder["some_key"] = 123456;

  json = JsonObject(proto);
  ASSERT_THAT(json.SetValueAsString("some_key", "hello"), IsOk());
  ASSERT_THAT(json.GetValueAsString("some_key"), IsOkAndHolds("hello"));
  ASSERT_THAT(json.GetValueAsNumber("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, KeyStringThenBoolOverwriteOK) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  // String then bool then string using protobuf builder.
  proto_builder["some_key"] = "hello";
  proto_builder["some_key"] = true;

  auto json = JsonObject(proto);
  ASSERT_THAT(json.GetValueAsBool("some_key"), IsOkAndHolds(true));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));

  // String then bool using protobuf builder then Json setter.
  proto_builder["some_key"] = "hello";

  json = JsonObject(proto);
  ASSERT_THAT(json.SetValueAsBool("some_key", true), IsOk());
  ASSERT_THAT(json.GetValueAsBool("some_key"), IsOkAndHolds(true));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(JsonObject, KeyStringThenTimeOverwriteOK) {
  google::protobuf::Struct proto;
  JsonStructBuilder proto_builder(&proto);
  // String then time then string using protobuf builder.
  absl::Time now = absl::Now();
  proto_builder["some_key"] = "hello";
  proto_builder["some_key"] = static_cast<int>(absl::ToUnixSeconds(now));

  auto json = JsonObject(proto);
  auto key_or = json.GetValueAsTime("some_key");
  ASSERT_THAT(key_or.status(), IsOk());
  auto value = key_or.ValueOrDie();
  ASSERT_LT(value, now + absl::Seconds(1));
  ASSERT_GT(value, now - absl::Seconds(1));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));

  // String then time using protobuf builder then Json setter.
  proto_builder["some_key"] = "hello";
  json = JsonObject(proto);
  ASSERT_THAT(json.SetValueAsTime("some_key", now), IsOk());

  key_or = json.GetValueAsTime("some_key");
  ASSERT_THAT(key_or.status(), IsOk());
  value = key_or.ValueOrDie();
  ASSERT_LT(value, now + absl::Seconds(1));
  ASSERT_GT(value, now - absl::Seconds(1));
  ASSERT_THAT(json.GetValueAsString("some_key").status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

}  // namespace tink
}  // namespace crypto
