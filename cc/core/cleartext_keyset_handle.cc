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

#include "cc/cleartext_keyset_handle.h"

#include <istream>

#include "cc/keyset_handle.h"
#include "cc/util/ptr_util.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "proto/tink.pb.h"

using google::crypto::tink::Keyset;

namespace crypto {
namespace tink {

//  static
util::StatusOr<std::unique_ptr<KeysetHandle>> CleartextKeysetHandle::New(
    const Keyset& keyset) {
  auto handle = util::make_unique<KeysetHandle>(keyset);
  return std::move(handle);
}

//  static
util::StatusOr<std::unique_ptr<KeysetHandle>> CleartextKeysetHandle::ParseFrom(
    const std::string& serialized_keyset) {
  Keyset keyset;
  if (!keyset.ParseFromString(serialized_keyset)) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Could not parse the input string as a Keyset-proto.");
  }
  return New(keyset);
}

//  static
util::StatusOr<std::unique_ptr<KeysetHandle>> CleartextKeysetHandle::ParseFrom(
    std::istream* keyset_stream) {
  Keyset keyset;
  if (!keyset.ParseFromIstream(keyset_stream)) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Could not parse the input stream as a Keyset-proto.");
  }
  return New(keyset);
}

}  // namespace tink
}  // namespace crypto
