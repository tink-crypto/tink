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

#include <string>

#include <google/protobuf/util/json_util.h>
#include "absl/status/status.h"
#include "absl/strings/substitute.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

namespace {

util::Status ConvertProtoStatus(const google::protobuf::util::Status& status) {
  return util::Status(static_cast<absl::StatusCode>(status.code()),
                                    std::string(status.message().data(), status.message().length()));
}

}  // namespace

util::StatusOr<google::protobuf::Struct> JsonStringToProtoStruct(
    absl::string_view json_string) {
  google::protobuf::Struct proto;
  google::protobuf::util::JsonParseOptions json_parse_options;
  auto status = google::protobuf::util::JsonStringToMessage(google::protobuf::StringPiece(json_string.data(), json_string.length()), &proto,
                                                  json_parse_options);
  if (!status.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid JSON");
  }
  return proto;
}

util::StatusOr<google::protobuf::ListValue> JsonStringToProtoList(
    absl::string_view json_string) {
  google::protobuf::ListValue proto;
  google::protobuf::util::JsonParseOptions json_parse_options;
  auto status = google::protobuf::util::JsonStringToMessage(google::protobuf::StringPiece(json_string.data(), json_string.length()), &proto,
                                                  json_parse_options);
  if (!status.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid JSON");
  }
  return proto;
}

util::StatusOr<std::string> ProtoStructToJsonString(
    const google::protobuf::Struct& proto) {
  std::string output;
  auto status = google::protobuf::util::MessageToJsonString(proto, &output);
  if (!status.ok()) {
    return ConvertProtoStatus(status);
  }
  return output;
}

util::StatusOr<std::string> ProtoListToJsonString(
    const google::protobuf::ListValue& proto) {
  std::string output;
  auto status = google::protobuf::util::MessageToJsonString(proto, &output);
  if (!status.ok()) {
    return ConvertProtoStatus(status);
  }
  return output;
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
