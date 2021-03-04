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

// Helper classes for building instances of google::protobuf::Struct and
// friends.
//
// The StructBuilder class lets you fill in a google::protobuf::Struct instance
// using a nicer syntax, which mimics the JSON data structure that Struct is
// trying to model:
//
//     google::protobuf::Struct result;
//     proto2::util::StructBuilder builder(&result);
//     // Use the assignment operator to add scalar fields.  It will
//     // automatically fill in the correct branch of the Value oneof,
//     // depending on what type you pass in.
//     builder["name"] = "John Doe";
//     builder["age"] = 34;
//     builder["has_children"] = false;
//     builder["date_of_death"] = nullptr;
//     // Structs of structs "just work".
//     builder["favorite_sports_team"]["sport"] = "baseball";
//     builder["favorite_sports_team"]["team"] = "Brooklyn Dodgers";
//     // You can also cache the "inner" struct if you need to.  (`team` will be
//     // an instance of ValueBuilder.)
//     auto team = builder["favorite_sports_team"];
//     team["league"] = "National League";
//     // Overwriting a struct with a primitive replaces the entire struct.
//     builder["favorite_food"]["name"] = "avocado";
//     builder["favorite_food"] = "avocado";
//     // Use append() to add elements to a list.
//     // You can use the same assignment operator to add scalars:
//     builder["favorite_numbers"].append() = 13;
//     // Or pass the value directly to append:
//     builder["favorite_numbers"].append(100);
//     // For adding a struct to a list, you need a temporary variable (which
//     // will be an instance of ValueBuilder):
//     auto email = builder["emails"].append();
//     email["type"] = "work";
//     email["email"] = "jdoe@example.com";
//
// Together, all of the above fills in `result` so that it's equivalent to the
// following JSON:
//
//     {
//       "name": "John Doe",
//       "age": 34,
//       "has_children": false,
//       "date_of_death": null,
//       "favorite_sports_team": {
//         "sport": "baseball",
//         "team": "Brooklyn Dodgers",
//         "league": "National League",
//       },
//       "favorite_food": "avocado",
//       "favorite_numbers": [13, 100],
//       "emails": [
//         { "type": "work", "email": "jdoe@example.com" }
//       ]
//     }

#ifndef TINK_JWT_STRUCT_UTIL_H_
#define TINK_JWT_STRUCT_UTIL_H_

#include "google/protobuf/struct.pb.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// A builder class for google::protobuf::Value.
class ValueBuilder {
 public:
  // Creates a new ValueBuilder that will fill in the contents of `value`.  We
  // do not take ownership of `value`; it must outlive this ValueBuilder, and
  // any child ValueBuilders created for subfields.
  explicit ValueBuilder(google::protobuf::Value* value) : value_(value) {}

  // Sets `value` to a boolean
  ValueBuilder& operator=(bool other) {
    value_->set_bool_value(other);
    return *this;
  }

  // Sets `value` to an int
  ValueBuilder& operator=(int other) {
    value_->set_number_value(other);
    return *this;
  }

  // Sets `value` to a double
  ValueBuilder& operator=(double other) {
    value_->set_number_value(other);
    return *this;
  }

  // Sets `value` to null
  ValueBuilder& operator=(std::nullptr_t other) {
    value_->set_null_value(google::protobuf::NULL_VALUE);
    return *this;
  }

  // Sets `value` to a string.  This overload is needed for string literals;
  // without it, the compiler would try to coerce the literal into a bool.
  ValueBuilder& operator=(const char* other) {
    value_->set_string_value(other);
    return *this;
  }

  // Sets `value` to a string.
  ValueBuilder& operator=(absl::string_view other) {
    value_->set_string_value(std::string(other));
    return *this;
  }

  // Copy content from other value.
  ValueBuilder& operator=(const google::protobuf::Value& other) {
    (*value_) = other;
    return *this;
  }

  // Forces `value` to be a list and copies content from another ListValue.
  ValueBuilder& operator=(const google::protobuf::ListValue& other) {
    google::protobuf::ListValue* list_value = value_->mutable_list_value();
    (*list_value) = other;
    return *this;
  }

  // Forces `value` to be a struct and copies content from another Struct.
  ValueBuilder& operator=(const google::protobuf::Struct& other) {
    google::protobuf::Struct* struct_value = value_->mutable_struct_value();
    (*struct_value) = other;
    return *this;
  }

  // Forces `value` to be a list, and adds a new element to it.  Returns a new
  // ValueBuilder for the new list element.
  ValueBuilder append() {
    google::protobuf::ListValue* list_value = value_->mutable_list_value();
    return ValueBuilder(list_value->add_values());
  }

  // Forces `value` to be a list, and adds a new scalar element to it.
  template <typename T>
  void append(T element) {
    append() = element;
  }

  // Forces `value` to be a struct, and ensures that there is a field with the
  // given `name`, creating it if necessary.  Returns a new ValueBuilder for the
  // field's value.
  ValueBuilder operator[](absl::string_view name) {
    google::protobuf::Struct* struct_value = value_->mutable_struct_value();
    return ValueBuilder(&(*struct_value->mutable_fields())[std::string(name)]);
  }

 private:
  google::protobuf::Value* value_;
};

// A builder class for google::protobuf::Struct.
class JsonStructBuilder {
 public:
  // Creates a new StructBuilder that will fill in the contents of
  // `unowned_struct`.  We do not take ownership of the Struct; it must outlive
  // this StructBuilder, and any ValueBuilders that are created for subfields.
  explicit JsonStructBuilder(google::protobuf::Struct* unowned_struct)
      : struct_(unowned_struct) {}

  // Ensures that the struct contains a field with the given `name`, creating it
  // if necessary.  Returns a new ValueBuilder for the field's value.
  ValueBuilder operator[](absl::string_view key) {
    return ValueBuilder(&(*struct_->mutable_fields())[std::string(key)]);
  }

 private:
  google::protobuf::Struct* struct_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_STRUCT_UTIL_H_
