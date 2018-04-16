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

#include "tink/json_keyset_writer.h"

#include <ostream>
#include <istream>
#include <sstream>

#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::Keyset;

namespace tinkutil = crypto::tink::util;

namespace crypto {
namespace tink {

namespace {

tinkutil::Status WriteProto(const portable_proto::Message& proto,
                        std::ostream* destination) {
  portable_proto::util::JsonPrintOptions json_options;
  json_options.add_whitespace = true;
  json_options.always_print_primitive_fields = true;
  std::string serialized_proto;
  auto status = portable_proto::util::MessageToJsonString(
      proto, &serialized_proto, json_options);
  if (!status.ok()) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
        "Conversion of the keyset to JSON failed: " + status.ToString());
  }
  (*destination) << serialized_proto;
  if (destination->fail()) {
    return tinkutil::Status(tinkutil::error::UNKNOWN,
                            "Error writing to the destination stream.");
  }
  return tinkutil::Status::OK;
}

}  // anonymous namespace


//  static
tinkutil::StatusOr<std::unique_ptr<JsonKeysetWriter>> JsonKeysetWriter::New(
    std::unique_ptr<std::ostream> destination_stream) {
  if (destination_stream == nullptr) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "destination_stream must be non-null.");
  }
  std::unique_ptr<JsonKeysetWriter> writer(
      new JsonKeysetWriter(std::move(destination_stream)));
  return std::move(writer);
}

tinkutil::Status JsonKeysetWriter::Write(const Keyset& keyset) {
  return WriteProto(keyset, destination_stream_.get());
}

tinkutil::Status JsonKeysetWriter::Write(
    const EncryptedKeyset& encrypted_keyset) {
  return WriteProto(encrypted_keyset, destination_stream_.get());
}

}  // namespace tink
}  // namespace crypto
