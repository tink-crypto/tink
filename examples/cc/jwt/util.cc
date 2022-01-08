// Copyright 2021 Google LLC
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

#include "jwt/util.h"

#include <fstream>
#include <iostream>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/util/status.h"

using crypto::tink::BinaryKeysetReader;
using crypto::tink::BinaryKeysetWriter;
using crypto::tink::CleartextKeysetHandle;
using crypto::tink::KeysetHandle;
using crypto::tink::KeysetReader;
using crypto::tink::KeysetWriter;

namespace {

// Returns a BinaryKeysetReader that reads from the specified file.
// In case of errors writes a log message and aborts.
std::unique_ptr<KeysetReader> GetBinaryKeysetReader(
    absl::string_view filename) {
  std::unique_ptr<std::ifstream> keyset_stream(new std::ifstream());
  keyset_stream->open(std::string(filename), std::ifstream::in);
  crypto::tink::util::StatusOr<std::unique_ptr<KeysetReader>> keyset_reader =
      BinaryKeysetReader::New(std::move(keyset_stream));
  if (!keyset_reader.ok()) {
    std::clog << "Creation of the BinaryKeysetReader failed: "
              << keyset_reader.status().message() << std::endl;
    exit(1);
  }
  return std::move(*keyset_reader);
}

// Returns a BinaryKeysetWriter that writes from the specified file.
// In case of errors writes a log message and aborts.
std::unique_ptr<KeysetWriter> GetBinaryKeysetWriter(
    absl::string_view filename) {
  std::unique_ptr<std::ofstream> keyset_stream(new std::ofstream());
  keyset_stream->open(std::string(filename), std::ofstream::out);
  crypto::tink::util::StatusOr<std::unique_ptr<BinaryKeysetWriter>>
      keyset_writer = BinaryKeysetWriter::New(std::move(keyset_stream));
  if (!keyset_writer.ok()) {
    std::clog << "Creation of the BinaryKeysetWriter failed: "
              << keyset_writer.status().message() << std::endl;
    exit(1);
  }
  return std::move(*keyset_writer);
}

}  // namespace

std::unique_ptr<KeysetHandle> ReadKeyset(absl::string_view filename) {
  std::unique_ptr<crypto::tink::KeysetReader> keyset_reader =
      GetBinaryKeysetReader(filename);
  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      CleartextKeysetHandle::Read(std::move(keyset_reader));
  if (!keyset_handle.ok()) {
    std::clog << "Reading the keyset failed: "
              << keyset_handle.status().message() << std::endl;
    exit(1);
  }
  return std::move(*keyset_handle);
}

void WriteKeyset(const crypto::tink::KeysetHandle& keyset_handle,
                 absl::string_view filename) {
  std::unique_ptr<crypto::tink::KeysetWriter> keyset_writer =
      GetBinaryKeysetWriter(filename);
  auto status =
      CleartextKeysetHandle::Write(keyset_writer.get(), keyset_handle);
  if (!status.ok()) {
    std::clog << "Writing the keyset failed: " << status.message() << std::endl;
    exit(1);
  }
}

std::string ReadFile(absl::string_view filename) {
  std::ifstream input_stream;
  input_stream.open(std::string(filename), std::ifstream::in);
  if (!input_stream.is_open()) {
    std::clog << "Error opening input file " << std::string(filename)
              << std::endl;
    exit(1);
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  input_stream.close();
  return input.str();
}

void WriteFile(absl::string_view output, absl::string_view filename) {
  std::ofstream output_stream(std::string(filename),
                              std::ofstream::out | std::ofstream::binary);
  if (!output_stream.is_open()) {
    std::clog << "Error opening output file " << std::string(filename)
              << std::endl;
    exit(1);
  }
  output_stream << std::string(output);
  output_stream.close();
}
