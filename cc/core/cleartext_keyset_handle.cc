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

#include "tink/cleartext_keyset_handle.h"

#include <istream>

#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using google::crypto::tink::Keyset;


namespace crypto {
namespace tink {

// static
util::StatusOr<std::unique_ptr<KeysetHandle>> CleartextKeysetHandle::Read(
    std::unique_ptr<KeysetReader> reader) {
  auto keyset_result = reader->Read();
  if (!keyset_result.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Error reading keyset data: %s",
                     keyset_result.status().message());
  }
  std::unique_ptr<KeysetHandle> handle(
      new KeysetHandle(std::move(keyset_result.ValueOrDie())));
  return std::move(handle);
}

// static
crypto::tink::util::Status CleartextKeysetHandle::Write(
    KeysetWriter* writer, const KeysetHandle& keyset_handle) {
  if (!writer) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Error KeysetWriter cannot be null");
  }
  return writer->Write(keyset_handle.get_keyset());
}

// static
std::unique_ptr<KeysetHandle> CleartextKeysetHandle::GetKeysetHandle(
    const Keyset& keyset) {
  auto unique_keyset = absl::make_unique<Keyset>(keyset);
  std::unique_ptr<KeysetHandle> handle =
      absl::WrapUnique(new KeysetHandle(std::move(unique_keyset)));
  return handle;
}

// static
const Keyset& CleartextKeysetHandle::GetKeyset(
    const KeysetHandle& keyset_handle) {
  return keyset_handle.get_keyset();
}

}  // namespace tink
}  // namespace crypto
