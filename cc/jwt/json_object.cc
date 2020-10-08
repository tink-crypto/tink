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

#include "tink/jwt/json_object.h"

#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/substitute.h"
#include "tink/jwt/json_struct_util.h"

namespace crypto {
namespace tink {

JsonObject::JsonObject(const google::protobuf::Struct& proto) {
  json_proto_ = proto;
}

JsonObject::JsonObject() {}

util::StatusOr<std::string> JsonObject::GetValueAsString(
    absl::string_view name) const {
  const auto it = json_proto_.fields().find(std::string(name));
  if (it == json_proto_.fields().cend()) {
    return crypto::tink::util::Status(
        util::error::NOT_FOUND, absl::Substitute("field '$0' not found", name));
  }

  if (it->second.kind_case() != google::protobuf::Value::kStringValue) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field $0' is not a string", name));
  }

  return it->second.string_value();
}

util::StatusOr<int> JsonObject::GetValueAsNumber(absl::string_view name) const {
  const auto it = json_proto_.fields().find(std::string(name));
  if (it == json_proto_.fields().cend()) {
    return crypto::tink::util::Status(
        util::error::NOT_FOUND, absl::Substitute("field '$0' not found", name));
  }

  if (it->second.kind_case() != google::protobuf::Value::kNumberValue) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is not a number", name));
  }

  return it->second.number_value();
}

util::StatusOr<absl::Time> JsonObject::GetValueAsTime(
    absl::string_view name) const {
  auto number_or = GetValueAsNumber(name);
  if (!number_or.status().ok()) {
    return number_or.status();
  }

  return absl::FromUnixSeconds(number_or.ValueOrDie());
}

util::StatusOr<std::vector<int>> JsonObject::GetValueAsNumberList(
    absl::string_view name) const {
  std::vector<int> vec;

  auto list_or = GetValueAsList(name);
  if (!list_or.status().ok()) {
    return list_or.status();
  }

  auto list = list_or.ValueOrDie();
  for (const auto& v : list->values()) {
    if (v.kind_case() != google::protobuf::Value::kNumberValue) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::Substitute(
              "field '$0' contains an element that is not a number", name));
    }
    vec.push_back(v.number_value());
  }

  return vec;
}

util::StatusOr<std::vector<std::string>> JsonObject::GetValueAsStringList(
    absl::string_view name) const {
  std::vector<std::string> vec;

  auto aud_list_or = GetValueAsList(name);
  if (!aud_list_or.status().ok()) {
    return aud_list_or.status();
  }

  auto aud_list = aud_list_or.ValueOrDie();
  for (const auto& v : aud_list->values()) {
    if (v.kind_case() != google::protobuf::Value::kStringValue) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::Substitute(
              "field '$0' contains an element that is not a string", name));
    }
    vec.push_back(v.string_value());
  }

  return vec;
}

util::StatusOr<const google::protobuf::ListValue*> JsonObject::GetValueAsList(
    absl::string_view name) const {
  const auto& it = json_proto_.fields().find(std::string(name));
  if (it == json_proto_.fields().cend()) {
    return crypto::tink::util::Status(
        util::error::NOT_FOUND, absl::Substitute("field '$0' not found", name));
  }

  if (it->second.kind_case() != google::protobuf::Value::kListValue) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is not a list", name));
  }

  return static_cast<const google::protobuf::ListValue*>(
      &it->second.list_value());
}

util::StatusOr<bool> JsonObject::GetValueAsBool(absl::string_view name) const {
  const auto& it = json_proto_.fields().find(std::string(name));
  if (it == json_proto_.fields().cend()) {
    return crypto::tink::util::Status(
        util::error::NOT_FOUND, absl::Substitute("field '$0' not found", name));
  }

  if (it->second.kind_case() != google::protobuf::Value::kBoolValue) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::Substitute("field '$0' is not a list", name));
  }

  return it->second.bool_value();
}

util::Status JsonObject::SetValueAsTime(absl::string_view name,
                                        absl::Time value) {
  JsonStructBuilder j_builder(&json_proto_);
  j_builder[name] = static_cast<int>(absl::ToUnixSeconds(value));
  return util::OkStatus();
}

util::Status JsonObject::SetValueAsNumber(absl::string_view name, int value) {
  JsonStructBuilder j_builder(&json_proto_);
  j_builder[name] = value;
  return util::OkStatus();
}

util::Status JsonObject::SetValueAsString(absl::string_view name,
                                          absl::string_view value) {
  JsonStructBuilder j_builder(&json_proto_);
  j_builder[name] = value;
  return util::OkStatus();
}

util::Status JsonObject::SetValueAsBool(absl::string_view name, bool value) {
  JsonStructBuilder j_builder(&json_proto_);
  j_builder[name] = value;
  return util::OkStatus();
}

util::Status JsonObject::AppendValueToStringList(absl::string_view name,
                                                 absl::string_view value) {
  JsonStructBuilder j_builder(&json_proto_);
  j_builder[name].append(value);
  return util::OkStatus();
}

util::Status JsonObject::AppendValueToNumberList(absl::string_view name,
                                                 int value) {
  JsonStructBuilder j_builder(&json_proto_);
  j_builder[name].append(value);
  return util::OkStatus();
}

util::StatusOr<std::string> JsonObject::ToString() {
  return JsonStructBuilder::ToString(json_proto_);
}

}  // namespace tink
}  // namespace crypto
