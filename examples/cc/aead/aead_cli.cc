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
// [START aead-example]
// A command-line utility for testing Tink AEAD.
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json_keyset_reader.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, mode, "", "Mode of operation {encrypt|decrypt}");
ABSL_FLAG(std::string, input_filename, "", "Filename to operate on");
ABSL_FLAG(std::string, output_filename, "", "Output file name");
ABSL_FLAG(std::string, associated_data, "", "Associated data for AEAD");

namespace {

using ::crypto::tink::Aead;
using ::crypto::tink::AeadConfig;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::JsonKeysetReader;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::KeysetReader;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

constexpr absl::string_view kEncrypt = "encrypt";
constexpr absl::string_view kDecrypt = "decrypt";

// Creates a KeysetReader that reads a JSON-formatted keyset
// from the given file.
StatusOr<std::unique_ptr<KeysetReader>> GetJsonKeysetReader(
    const std::string& filename) {
  std::clog << "Creating a JsonKeysetReader...\n";
  auto key_input_stream = absl::make_unique<std::ifstream>();
  key_input_stream->open(filename, std::ifstream::in);
  return JsonKeysetReader::New(std::move(key_input_stream));
}

// Creates a KeysetHandle that for a keyset read from the given file,
// which is expected to contain a JSON-formatted keyset.
StatusOr<std::unique_ptr<KeysetHandle>> ReadKeyset(
    const std::string& filename) {
  StatusOr<std::unique_ptr<KeysetReader>> keyset_reader =
      GetJsonKeysetReader(filename);
  if (!keyset_reader.ok()) {
    return keyset_reader.status();
  }
  return CleartextKeysetHandle::Read(*std::move(keyset_reader));
}

// Reads `filename` and returns the read content as a string, or an error status
// if the file does not exist.
StatusOr<std::string> Read(const std::string& filename) {
  std::clog << "Reading the input...\n";
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

// Writes the given `data_to_write` to the specified file `filename`.
Status Write(const std::string& data_to_write, const std::string& filename) {
  std::clog << "Writing the output...\n";
  std::ofstream output_stream(filename,
                              std::ofstream::out | std::ofstream::binary);
  if (!output_stream.is_open()) {
    return Status(absl::StatusCode::kInternal,
                  absl::StrCat("Error opening output file ", filename));
  }
  output_stream << data_to_write;
  return crypto::tink::util::OkStatus();
}

}  // namespace

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string input_filename = absl::GetFlag(FLAGS_input_filename);
  std::string output_filename = absl::GetFlag(FLAGS_output_filename);
  std::string associated_data = absl::GetFlag(FLAGS_associated_data);

  if (mode.empty()) {
    std::cerr << "Mode must be specified with --mode=<" << kEncrypt << "|"
              << kDecrypt << ">." << std::endl;
    exit(1);
  }

  if (mode != kEncrypt && mode != kDecrypt) {
    std::cerr << "Unknown mode '" << mode << "'; "
              << "Expected either " << kEncrypt << " or " << kDecrypt << "."
              << std::endl;
    exit(1);
  }
  std::clog << "Using keyset from file " << keyset_filename << " to AEAD-"
            << mode << " file " << input_filename << " with associated data '"
            << associated_data << "'." << std::endl;
  std::clog << "The resulting output will be written to " << output_filename
            << std::endl;

  Status result = AeadConfig::Register();
  if (!result.ok()) {
    std::cerr << result.message() << std::endl;
    exit(1);
  }

  // Read the keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadKeyset(keyset_filename);
  if (!keyset_handle.ok()) {
    std::cerr << keyset_handle.status().message() << std::endl;
    exit(1);
  }

  // Get the primitive.
  StatusOr<std::unique_ptr<Aead>> aead_primitive =
      (*keyset_handle)->GetPrimitive<Aead>();
  if (!aead_primitive.ok()) {
    std::cerr << aead_primitive.status().message() << std::endl;
    exit(1);
  }

  // Read the input.
  StatusOr<std::string> input_file_content = Read(input_filename);
  if (!input_file_content.ok()) {
    std::cerr << input_file_content.status().message() << std::endl;
    exit(1);
  }

  // Compute the output.
  std::clog << mode << "ing...\n";
  std::string output;
  if (mode == kEncrypt) {
    StatusOr<std::string> encrypt_result =
        (*aead_primitive)->Encrypt(*input_file_content, associated_data);
    if (!encrypt_result.ok()) {
      std::cerr << encrypt_result.status().message() << std::endl;
      exit(1);
    }
    output = encrypt_result.value();
  } else {  // operation == kDecrypt.
    StatusOr<std::string> decrypt_result =
        (*aead_primitive)->Decrypt(*input_file_content, associated_data);
    if (!decrypt_result.ok()) {
      std::cerr << decrypt_result.status().message() << std::endl;
      exit(1);
    }
    output = decrypt_result.value();
  }

  // Write the output to the output file.
  Status write_result = Write(output, output_filename);
  if (!write_result.ok()) {
    std::cerr << write_result.message() << std::endl;
    exit(1);
  }

  std::clog << "All done." << std::endl;
  return 0;
}
// [END aead-example]
