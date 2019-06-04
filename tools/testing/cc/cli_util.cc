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

#include "tools/testing/cc/cli_util.h"

#include <iostream>
#include <fstream>
#include <sstream>

#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/json_keyset_reader.h"
#include "tink/json_keyset_writer.h"
#include "tink/config.h"
#include "tink/input_stream.h"
#include "tink/keyset_handle.h"
#include "tink/output_stream.h"
#include "tink/config/tink_config.h"
#include "tink/util/status.h"

using crypto::tink::BinaryKeysetReader;
using crypto::tink::BinaryKeysetWriter;
using crypto::tink::CleartextKeysetHandle;
using crypto::tink::Config;
using crypto::tink::InputStream;
using crypto::tink::JsonKeysetReader;
using crypto::tink::JsonKeysetWriter;
using crypto::tink::KeysetHandle;
using crypto::tink::KeysetReader;
using crypto::tink::KeysetWriter;
using crypto::tink::OutputStream;
using crypto::tink::TinkConfig;

namespace {

// Writes 'contents' of the specified 'size' to 'output_stream'.
// In case of errors writes a log message and aborts.
void WriteToStream(OutputStream* output_stream,
                   const void* contents,
                   int size) {
  if (output_stream == nullptr) {
      std::clog << "'output_stream' must be non-null" << std::endl;
      exit(1);
  }
  void* buffer;
  int pos = 0;
  int remaining = size;
  int available_space;
  int available_bytes;
  while (remaining > 0) {
    auto next_result = output_stream->Next(&buffer);
    if (!next_result.ok()) {
      std::clog << "Error writing to a stream: "
                << next_result.status() << std::endl;
      exit(1);
    }
    available_space = next_result.ValueOrDie();
    available_bytes = std::min(available_space, remaining);
    memcpy(buffer, reinterpret_cast<const char*>(contents) + pos,
           available_bytes);
    remaining -= available_bytes;
    pos += available_bytes;
  }
  if (available_space > available_bytes) {
    output_stream->BackUp(available_space - available_bytes);
  }
}

}  // namespace

// static
std::unique_ptr<KeysetReader> CliUtil::GetBinaryKeysetReader(
    const std::string& filename) {
  std::clog << "Creating a BinaryKeysetReader...\n";
  std::unique_ptr<std::ifstream> keyset_stream(new std::ifstream());
  keyset_stream->open(filename, std::ifstream::in);
  auto keyset_reader_result = BinaryKeysetReader::New(std::move(keyset_stream));
  if (!keyset_reader_result.ok()) {
    std::clog << "Creation of the reader failed: "
              << keyset_reader_result.status().error_message() << std::endl;
    exit(1);
  }
  return std::move(keyset_reader_result.ValueOrDie());
}

// static
std::unique_ptr<KeysetReader> CliUtil::GetJsonKeysetReader(
    const std::string& filename) {
  std::clog << "Creating a JsonKeysetReader...\n";
  std::unique_ptr<std::ifstream> keyset_stream(new std::ifstream());
  keyset_stream->open(filename, std::ifstream::in);
  auto keyset_reader_result = JsonKeysetReader::New(std::move(keyset_stream));
  if (!keyset_reader_result.ok()) {
    std::clog << "Creation of the reader failed: "
              << keyset_reader_result.status().error_message() << std::endl;
    exit(1);
  }
  return std::move(keyset_reader_result.ValueOrDie());
}

// static
std::unique_ptr<KeysetWriter> CliUtil::GetBinaryKeysetWriter(
    const std::string& filename) {
  std::clog << "Creating a BinaryKeysetWriter...\n";
  std::unique_ptr<std::ofstream> keyset_stream(new std::ofstream());
  keyset_stream->open(filename, std::ofstream::out);
  auto keyset_writer_result = BinaryKeysetWriter::New(std::move(keyset_stream));
  if (!keyset_writer_result.ok()) {
    std::clog << "Creation of the writer failed: "
              << keyset_writer_result.status().error_message() << std::endl;
    exit(1);
  }
  return std::move(keyset_writer_result.ValueOrDie());
}

// static
std::unique_ptr<KeysetWriter> CliUtil::GetJsonKeysetWriter(
    const std::string& filename) {
  std::clog << "Creating a JsonKeysetWriter...\n";
  std::unique_ptr<std::ofstream> keyset_stream(new std::ofstream());
  keyset_stream->open(filename, std::ifstream::out);
  auto keyset_writer_result = JsonKeysetWriter::New(std::move(keyset_stream));
  if (!keyset_writer_result.ok()) {
    std::clog << "Creation of the writer failed: "
              << keyset_writer_result.status().error_message() << std::endl;
    exit(1);
  }
  return std::move(keyset_writer_result.ValueOrDie());
}

// static
std::unique_ptr<KeysetHandle> CliUtil::ReadKeyset(const std::string& filename) {
  auto keyset_reader = GetBinaryKeysetReader(filename);
  auto keyset_handle_result =
      CleartextKeysetHandle::Read(std::move(keyset_reader));
  if (!keyset_handle_result.ok()) {
    std::clog << "Reading the keyset failed: "
              << keyset_handle_result.status().error_message() << std::endl;
    exit(1);
  }
  return std::move(keyset_handle_result.ValueOrDie());
}

// static
void CliUtil::InitTink() {
  std::clog << "Initializing Tink...\n";
  auto status = TinkConfig::Register();
  if (!status.ok()) {
    std::clog << "Initialization of Tink failed: "
              << status.error_message() << std::endl;
    exit(1);
  }
}

// static
std::string CliUtil::Read(const std::string& filename) {
  std::clog << "Reading the input...\n";
  std::ifstream input_stream;
  input_stream.open(filename, std::ifstream::in);
  if (!input_stream.is_open()) {
    std::clog << "Error opening input file " << filename << std::endl;
    exit(1);
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  input_stream.close();
  return input.str();
}

// static
void CliUtil::Write(const std::string& output,
                    const std::string& filename) {
  std::clog << "Writing the output...\n";
  std::ofstream output_stream(filename,
                              std::ofstream::out | std::ofstream::binary);
  if (!output_stream.is_open()) {
    std::clog << "Error opening output file " << filename << std::endl;
    exit(1);
  }
  output_stream << output;
  output_stream.close();
}

// static
void CliUtil::CopyStream(InputStream* input_stream,
                          OutputStream* output_stream) {
  if (input_stream == nullptr || output_stream == nullptr) {
      std::clog << "'input_stream' and 'output_stream' must be non-null"
                << std::endl;
      exit(1);
  }
  const void* in_buffer;
  while (true) {
    auto next_result = input_stream->Next(&in_buffer);
    if (next_result.status().error_code() ==
        crypto::tink::util::error::OUT_OF_RANGE) {
      // End of stream.
      auto status = output_stream->Close();
      if (!status.ok()) {
        std::clog << "Error closing the output stream: " << status << std::endl;
        exit(1);
      }
      return;
    }
    if (!next_result.ok()) {
      std::clog << "Error reading from a stream: "
                << next_result.status() << std::endl;
      exit(1);
    }
    auto read_bytes = next_result.ValueOrDie();
    if (read_bytes > 0) {
      WriteToStream(output_stream, in_buffer, read_bytes);
    }
  }
}
