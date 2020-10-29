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

#ifndef TINK_JWT_JSON_OBJECT_H_
#define TINK_JWT_JSON_OBJECT_H_

#include "google/protobuf/struct.pb.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/jwt/json_field_types.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Utility getters and setters for a JSON object.
// This class encapsulates a protobuf object
// This is intended for internal use only.
// The getter functions:
// - return util::error::NOT_FOUND if the requested header
// or claim does not exist.
// - return util::error::INVALID_ARGUMENT if the type of
// the requested header or claim does not match.
class JsonObject {
 public:
  explicit JsonObject(const google::protobuf::Struct& proto);
  JsonObject();

  // Getters.
  util::StatusOr<std::string> GetValueAsString(absl::string_view name) const;
  util::StatusOr<absl::Time> GetValueAsTime(absl::string_view name) const;
  util::StatusOr<std::vector<std::string>> GetValueAsStringList(
      absl::string_view name) const;
  util::StatusOr<std::vector<int>> GetValueAsNumberList(
      absl::string_view name) const;
  util::StatusOr<bool> GetValueAsBool(absl::string_view name) const;
  util::StatusOr<int> GetValueAsNumber(absl::string_view name) const;

  // Setters.
  util::Status SetValueAsTime(absl::string_view name, absl::Time value);
  util::Status SetValueAsNumber(absl::string_view name, int value);
  util::Status SetValueAsString(absl::string_view name,
                                absl::string_view value);
  util::Status SetValueAsBool(absl::string_view name, bool value);
  // Note: If the list is empty, AppendToXXXList() automatically
  // creates an empty list and appends 'value' to it.
  util::Status AppendValueToStringList(absl::string_view name,
                                       absl::string_view value);
  util::Status AppendValueToNumberList(absl::string_view name, int value);

  // Serialize.
  util::StatusOr<std::string> ToString();

  // List of field names and their type.
  util::StatusOr<absl::flat_hash_map<std::string, enum JsonFieldType>>
  getFieldNamesAndTypes();

 private:
  // Helper functions.
  util::StatusOr<const google::protobuf::ListValue*> GetValueAsList(
      absl::string_view name) const;

 private:
  google::protobuf::Struct json_proto_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JSON_OBJECT_H_
