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

#include "tink/binary_keyset_reader.h"

#include <iostream>
#include <istream>
#include <sstream>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::Keyset;

//  static
util::StatusOr<std::unique_ptr<KeysetReader>> BinaryKeysetReader::New(
    std::unique_ptr<std::istream> keyset_stream) {
  if (keyset_stream == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "keyset_stream must be non-null.");
  }
  std::stringstream buffer;
  buffer << keyset_stream->rdbuf();
  return New(buffer.str());
}

//  static
util::StatusOr<std::unique_ptr<KeysetReader>> BinaryKeysetReader::New(
    absl::string_view serialized_keyset) {
  std::unique_ptr<KeysetReader> reader(
      new BinaryKeysetReader(serialized_keyset));
  return std::move(reader);
}

util::StatusOr<std::unique_ptr<Keyset>> BinaryKeysetReader::Read() {
  auto keyset = absl::make_unique<Keyset>();
  if (!keyset->ParseFromString(serialized_keyset_)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Could not parse the input stream as a Keyset-proto.");
  }
  return std::move(keyset);
}

util::StatusOr<std::unique_ptr<EncryptedKeyset>>
BinaryKeysetReader::ReadEncrypted() {
  auto enc_keyset = absl::make_unique<EncryptedKeyset>();
  if (!enc_keyset->ParseFromString(serialized_keyset_)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Could not parse the input stream as an EncryptedKeyset-proto.");
  }
  return std::move(enc_keyset);
}

}  // namespace tink
}  // namespace crypto
