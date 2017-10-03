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

#include "cc/binary_keyset_reader.h"

#include <iostream>
#include <istream>
#include <sstream>

#include "cc/util/errors.h"
#include "cc/util/ptr_util.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::Keyset;

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

//  static
util::StatusOr<std::unique_ptr<BinaryKeysetReader>> BinaryKeysetReader::New(
    std::unique_ptr<std::istream> keyset_stream) {
  if (keyset_stream == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "keyset_stream must be non-null.");
  }
  std::unique_ptr<BinaryKeysetReader> reader(
      new BinaryKeysetReader(std::move(keyset_stream)));
  return std::move(reader);
}

//  static
util::StatusOr<std::unique_ptr<BinaryKeysetReader>> BinaryKeysetReader::New(
    google::protobuf::StringPiece serialized_keyset) {
  std::unique_ptr<std::istream> keyset_stream(
      new std::stringstream(std::string(serialized_keyset), std::ios_base::in));
  return New(std::move(keyset_stream));
}


util::StatusOr<std::unique_ptr<Keyset>> BinaryKeysetReader::Read() {
  auto keyset = util::make_unique<Keyset>();
  if (!keyset->ParseFromIstream(keyset_stream_.get())) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Could not parse the input stream as a Keyset-proto.");
  }
  return std::move(keyset);
}

util::StatusOr<std::unique_ptr<EncryptedKeyset>>
BinaryKeysetReader::ReadEncrypted() {
  auto enc_keyset = util::make_unique<EncryptedKeyset>();
  if (!enc_keyset->ParseFromIstream(keyset_stream_.get())) {
    return util::Status(util::error::INVALID_ARGUMENT,
        "Could not parse the input stream as an EncryptedKeyset-proto.");
  }
  return std::move(enc_keyset);
}

}  // namespace tink
}  // namespace crypto
