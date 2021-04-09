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

#ifndef TINK_JWT_INTERNAL_JWT_UTIL_H_
#define TINK_JWT_INTERNAL_JWT_UTIL_H_

#include "google/protobuf/struct.pb.h"
#include "absl/strings/substitute.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

util::StatusOr<google::protobuf::Struct> JsonStringToProtoStruct(
    absl::string_view json_string);

util::StatusOr<google::protobuf::ListValue> JsonStringToProtoList(
    absl::string_view json_string);

util::StatusOr<std::string> ProtoStructToJsonString(
    const google::protobuf::Struct& proto);

util::StatusOr<std::string> ProtoListToJsonString(
    const google::protobuf::ListValue& proto);

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_UTIL_H_
