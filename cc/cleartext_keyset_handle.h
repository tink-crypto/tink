// Copyright 2017 Google Inc.
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

#ifndef TINK_CLEARTEXT_KEYSET_HANDLE_H_
#define TINK_CLEARTEXT_KEYSET_HANDLE_H_

#include <istream>
#include <memory>
#include <sstream>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Creates keyset handles from cleartext keysets. This API allows
// loading cleartext keysets, thus its usage should be restricted.
class CleartextKeysetHandle {
 public:
  // Creates a KeysetHandle with a keyset obtained via `reader`. Optionally
  // allows to pass monitoring_annotations to attach additional data to the
  // resulting KeysetHandle, which will be used for monitoring.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> Read(
      std::unique_ptr<KeysetReader> reader,
      const absl::flat_hash_map<std::string, std::string>&
          monitoring_annotations = {});

  // Writes the keyset in the given `keyset_handle` to the `writer` which must
  // be non-null.
  static crypto::tink::util::Status Write(KeysetWriter* writer,
                                          const KeysetHandle& keyset_handle);

  // Creates a KeysetHandle object for the given 'keyset'.
  static std::unique_ptr<KeysetHandle> GetKeysetHandle(
      const google::crypto::tink::Keyset& keyset);

  // Returns a Keyset-proto from the given 'keyset_handle'.
  static const google::crypto::tink::Keyset& GetKeyset(
      const KeysetHandle& keyset_handle);

 private:
  CleartextKeysetHandle() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CLEARTEXT_KEYSET_HANDLE_H_
