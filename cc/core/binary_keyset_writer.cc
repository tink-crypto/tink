// Copyright 2018 Google Inc.
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

#include "tink/binary_keyset_writer.h"

#include <ostream>
#include <istream>
#include <sstream>

#include "absl/status/status.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::Keyset;


namespace crypto {
namespace tink {

namespace {

util::Status WriteProto(const portable_proto::MessageLite& proto,
                        std::ostream* destination) {
  std::string serialized_proto;
  (*destination) << proto.SerializeAsString();
  if (destination->fail()) {
    return util::Status(util::error::UNKNOWN,
                        "Error writing to the destination stream.");
  }
  return util::OkStatus();
}

}  // anonymous namespace


//  static
util::StatusOr<std::unique_ptr<BinaryKeysetWriter>> BinaryKeysetWriter::New(
    std::unique_ptr<std::ostream> destination_stream) {
  if (destination_stream == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "destination_stream must be non-null.");
  }
  std::unique_ptr<BinaryKeysetWriter> writer(
      new BinaryKeysetWriter(std::move(destination_stream)));
  return std::move(writer);
}

util::Status BinaryKeysetWriter::Write(const Keyset& keyset) {
  return WriteProto(keyset, destination_stream_.get());
}

util::Status BinaryKeysetWriter::Write(
    const EncryptedKeyset& encrypted_keyset) {
  return WriteProto(encrypted_keyset, destination_stream_.get());
}

}  // namespace tink
}  // namespace crypto
