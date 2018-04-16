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

#include "tink/json_keyset_reader.h"

#include <iostream>
#include <istream>
#include <sstream>

#include "absl/memory/memory.h"
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

//  static
tinkutil::StatusOr<std::unique_ptr<JsonKeysetReader>> JsonKeysetReader::New(
    std::unique_ptr<std::istream> keyset_stream) {
  if (keyset_stream == nullptr) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "keyset_stream must be non-null.");
  }
  std::unique_ptr<JsonKeysetReader> reader(
      new JsonKeysetReader(std::move(keyset_stream)));
  return std::move(reader);
}

//  static
tinkutil::StatusOr<std::unique_ptr<JsonKeysetReader>> JsonKeysetReader::New(
    absl::string_view serialized_keyset) {
  std::unique_ptr<JsonKeysetReader>
      reader(new JsonKeysetReader(serialized_keyset));
  return std::move(reader);
}

tinkutil::StatusOr<std::unique_ptr<Keyset>> JsonKeysetReader::Read() {
  std::string serialized_keyset_from_stream;
  std::string* serialized_keyset;
  if (keyset_stream_ == nullptr) {
    serialized_keyset = &serialized_keyset_;
  } else {
    serialized_keyset_from_stream = std::string(
        std::istreambuf_iterator<char>(*keyset_stream_), {});
    serialized_keyset = &serialized_keyset_from_stream;
  }
  auto keyset = absl::make_unique<Keyset>();
  auto status = portable_proto::util::JsonStringToMessage(
      *serialized_keyset, keyset.get());
  if (!status.ok()) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
        "Could not parse the input stream as a JSON Keyset-proto.");
  }
  return std::move(keyset);
}

tinkutil::StatusOr<std::unique_ptr<EncryptedKeyset>>
JsonKeysetReader::ReadEncrypted() {
  std::string serialized_keyset_from_stream;
  std::string* serialized_keyset;
  if (keyset_stream_ == nullptr) {
    serialized_keyset = &serialized_keyset_;
  } else {
    serialized_keyset_from_stream = std::string(
        std::istreambuf_iterator<char>(*keyset_stream_), {});
    serialized_keyset = &serialized_keyset_from_stream;
  }
  auto enc_keyset = absl::make_unique<EncryptedKeyset>();
  auto status = portable_proto::util::JsonStringToMessage(
      *serialized_keyset, enc_keyset.get());
  if (!status.ok()) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
        "Could not parse the input stream as a JSON EncryptedKeyset-proto.");
  }
  return std::move(enc_keyset);
}

}  // namespace tink
}  // namespace crypto
