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

#ifndef TINK_INTERNAL_SERIALIZATION_H_
#define TINK_INTERNAL_SERIALIZATION_H_

#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {

// Represents either a serialized `Key` or a serialized `Parameters` object.
//
// Serialization objects are used within Tink to serialize keys, keysets, and
// parameters. For each serialization method (e.g., binary protobuf
// serialization), one subclass of this interface must be defined.
//
// This class should eventually be moved to the Tink Public API, but major
// changes still might be made until then (i.e., don't assume that this API
// is completely stable yet).
class Serialization {
 public:
  // Identifies which parsing method to use in the registry.
  //
  // When registering a parsing function in the registry, one argument will be
  // this object identifier. When the registry is asked to parse a
  // `Serialization`, the registry will then dispatch it to the corresponding
  // method.
  //
  // The returned absl::string_view must remain valid for the lifetime of this
  // `Serialization` object.
  virtual absl::string_view ObjectIdentifier() const = 0;

  virtual ~Serialization() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SERIALIZATION_H_
