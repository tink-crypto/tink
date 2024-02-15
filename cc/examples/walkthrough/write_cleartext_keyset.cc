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

#include "walkthrough/write_cleartext_keyset.h"

// [START tink_walkthrough_write_keyset]
#include <memory>
#include <ostream>
#include <utility>

#include "absl/status/status.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json_keyset_writer.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

namespace tink_walkthrough {

using ::crypto::tink::JsonKeysetWriter;
using ::crypto::tink::util::StatusOr;

// Writes a `keyset` to `output_stream` as a plaintext JSON format.
//
// Warning: Storing keys in cleartext is not recommended. We recommend using a
// Key Management Service to protect your keys. See
// https://github.com/google/tink/blob/master/cc/examples/walkthrough/write_keyset.cc
// for an example, and
// https://developers.google.com/tink/key-management-overview for more info on
// how to use a KMS with Tink.
//
// Prerequisites for this example:
//  - Create a keyset and obtain a KeysetHandle to it.
crypto::tink::util::Status WriteKeyset(
    const crypto::tink::KeysetHandle& keyset,
    std::unique_ptr<std::ostream> output_stream) {
  StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer =
      JsonKeysetWriter::New(std::move(output_stream));
  if (!keyset_writer.ok()) return keyset_writer.status();
  return crypto::tink::CleartextKeysetHandle::Write((keyset_writer)->get(),
                                                    keyset);
}

}  // namespace tink_walkthrough
// [END tink_walkthrough_write_keyset]
