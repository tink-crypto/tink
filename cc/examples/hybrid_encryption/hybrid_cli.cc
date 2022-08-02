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
// [START hybrid-example]
// A command-line utility for testing Tink Hybrid Encryption.

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
#include "tink/cleartext_keyset_handle.h"
#include "tink/hybrid/hpke_config.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/json_keyset_reader.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, mode, "", "Mode of operation {encrypt|decrypt}");
ABSL_FLAG(std::string, input_filename, "", "Input file name");
ABSL_FLAG(std::string, output_filename, "", "Output file name");
ABSL_FLAG(std::string, context_info, "",
          "Context info for Hybrid Encryption/Decryption");

namespace {

using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::HybridDecrypt;
using ::crypto::tink::HybridEncrypt;
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
  std::string context_info = absl::GetFlag(FLAGS_context_info);

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
  std::clog << "Using keyset from file " << keyset_filename << " to hybrid "
            << mode << " file " << input_filename << " with context info '"
            << context_info << "'." << std::endl;
  std::clog << "The resulting output will be written to " << output_filename
            << std::endl;

  Status result = crypto::tink::RegisterHpke();
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
    // Get the hybrid encryption primitive.
    StatusOr<std::unique_ptr<HybridEncrypt>> hybrid_encrypt_primitive =
        (*keyset_handle)->GetPrimitive<HybridEncrypt>();
    if (!hybrid_encrypt_primitive.ok()) {
      std::cerr << hybrid_encrypt_primitive.status().message() << std::endl;
      exit(1);
    }
    // Generate the ciphertext.
    StatusOr<std::string> encrypt_result =
        (*hybrid_encrypt_primitive)->Encrypt(*input_file_content, context_info);
    if (!encrypt_result.ok()) {
      std::cerr << encrypt_result.status().message() << std::endl;
      exit(1);
    }
    output = encrypt_result.value();
  } else {  // operation == kDecrypt.
    // Get the hybrid decryption primitive.
    StatusOr<std::unique_ptr<HybridDecrypt>> hybrid_decrypt_primitive =
        (*keyset_handle)->GetPrimitive<HybridDecrypt>();
    if (!hybrid_decrypt_primitive.ok()) {
      std::cerr << hybrid_decrypt_primitive.status().message() << std::endl;
      exit(1);
    }
    // Recover the plaintext.
    StatusOr<std::string> decrypt_result =
        (*hybrid_decrypt_primitive)->Decrypt(*input_file_content, context_info);
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
// [END hybrid-example]
