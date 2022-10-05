// Copyright 2022 Google LLC
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

#include "walkthrough/load_cleartext_keyset.h"

// [START tink_walkthrough_load_cleartext_keyset]
#include <iostream>
#include <memory>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json_keyset_reader.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/util/statusor.h"

namespace tink_walkthrough {

using ::crypto::tink::util::StatusOr;

// Loads a JSON-serialized unencrypted keyset `serialized_keyset` and returns a
// KeysetHandle.
//
// Prerequisites for this example:
//  - Create an plaintext keyset in JSON, for example, using Tinkey:
//
//    tinkey create-key --key-template AES256_GCM \
//      --out-format json --out keyset.json
//
StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>> LoadKeyset(
    absl::string_view serialized_keyset) {
  // To load a serialized keyset we need a JSON keyset reader.
  StatusOr<std::unique_ptr<crypto::tink::KeysetReader>> reader =
      crypto::tink::JsonKeysetReader::New(serialized_keyset);
  if (!reader.ok()) {
    return reader.status();
  }
  // Parse and obtain the keyset using the reader.
  return crypto::tink::CleartextKeysetHandle::Read(*std::move(reader));
}

}  // namespace tink_walkthrough
// [END tink_walkthrough_load_cleartext_keyset]
