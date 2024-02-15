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
#include "util/util.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json_keyset_reader.h"
#include "tink/json_keyset_writer.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace tink_cc_examples {
namespace {

using ::crypto::tink::JsonKeysetReader;
using ::crypto::tink::JsonKeysetWriter;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::KeysetReader;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

// Creates a KeysetReader that reads a JSON-formatted keyset
// from the given file.
StatusOr<std::unique_ptr<KeysetReader>> GetJsonKeysetReader(
    const std::string& filename) {
  auto input_stream = absl::make_unique<std::ifstream>();
  input_stream->open(filename, std::ifstream::in);
  return JsonKeysetReader::New(std::move(input_stream));
}

StatusOr<std::unique_ptr<JsonKeysetWriter>> GetJsonKeysetWriter(
    const std::string& filename) {
  auto output_stream = absl::make_unique<std::ofstream>();
  output_stream->open(filename, std::ofstream::out);
  return JsonKeysetWriter::New(std::move(output_stream));
}

}  // namespace

StatusOr<std::unique_ptr<KeysetHandle>> ReadJsonCleartextKeyset(
    const std::string& filename) {
  StatusOr<std::unique_ptr<KeysetReader>> keyset_reader =
      GetJsonKeysetReader(filename);
  if (!keyset_reader.ok()) return keyset_reader.status();
  return crypto::tink::CleartextKeysetHandle::Read(*std::move(keyset_reader));
}

Status WriteJsonCleartextKeyset(const std::string& filename,
                                const KeysetHandle& keyset_handle) {
  StatusOr<std::unique_ptr<JsonKeysetWriter>> keyset_writer =
      GetJsonKeysetWriter(filename);
  if (!keyset_writer.ok()) return keyset_writer.status();
  return crypto::tink::CleartextKeysetHandle::Write(keyset_writer->get(),
                                                    keyset_handle);
}

StatusOr<std::string> ReadFile(const std::string& filename) {
  std::ifstream input_stream;
  input_stream.open(filename, std::ifstream::in);
  if (!input_stream.is_open()) {
    return Status(absl::StatusCode::kInternal,
                  absl::StrCat("Error opening input file ", filename));
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  return input.str();
}

Status WriteToFile(const std::string& data_to_write,
                   const std::string& filename) {
  std::ofstream output_stream(filename,
                              std::ofstream::out | std::ofstream::binary);
  if (!output_stream.is_open()) {
    return Status(absl::StatusCode::kInternal,
                  absl::StrCat("Error opening output file ", filename));
  }
  output_stream << data_to_write;
  return crypto::tink::util::OkStatus();
}

}  // namespace tink_cc_examples
