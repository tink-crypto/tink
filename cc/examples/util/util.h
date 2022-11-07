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
#ifndef TINK_EXAMPLES_UTIL_UTIL_H_
#define TINK_EXAMPLES_UTIL_UTIL_H_

#include <memory>
#include <string>

#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace tink_cc_examples {

// Reads a keyset from the given file `filename` which is expected to contain a
// JSON-formatted keyset.
crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>>
ReadJsonCleartextKeyset(const std::string& filename);

// Writes `keyset_handle` to the file `filename` formatted with JSON in
// cleartext.
crypto::tink::util::Status WriteJsonCleartextKeyset(
    const std::string& filename,
    const crypto::tink::KeysetHandle& keyset_handle);

// Reads `filename` and returns the read content as a string, or an error status
// if the file does not exist.
crypto::tink::util::StatusOr<std::string> ReadFile(const std::string& filename);

// Writes the given `data_to_write` to the specified file `filename`.
crypto::tink::util::Status WriteToFile(const std::string& data_to_write,
                                       const std::string& filename);

}  // namespace tink_cc_examples

#endif  // TINK_EXAMPLES_UTIL_UTIL_H_
