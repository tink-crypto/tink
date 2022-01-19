// Copyright 2018 Google LLC
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

// A command-line utility for testing Tink-primitives.
// It requires 5 arguments:
//   keyset-file:  name of the file with the keyset to be used for encryption
//   operation: the actual AEAD-operation, i.e. "encrypt" or "decrypt"
//   input-file:  name of the file with input (plaintext for encryption, or
//                or ciphertext for decryption)
//   associated-data:  a string to be used as assciated data
//   output-file:  name of the file for the resulting output

#include <iostream>
#include <fstream>
#include <sstream>

#include "tink/aead.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/config.h"
#include "tink/json_keyset_reader.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/config/tink_config.h"

namespace {

// Helper functions.
// Upon failure each function writes an error message, and terminates.

// Initializes Tink.
void InitTink() {
  std::clog << "Initializing Tink...\n";
  auto status = crypto::tink::TinkConfig::Register();
  if (!status.ok()) {
    std::clog << "Initialization of Tink failed: " << status.message()
              << std::endl;
    exit(1);
  }
}

// Creates a KeysetReader that reads a JSON-formatted keyset
// from the given file.
std::unique_ptr<crypto::tink::KeysetReader> GetJsonKeysetReader(
    const std::string& filename) {
  std::clog << "Creating a JsonKeysetReader...\n";
  std::unique_ptr<std::ifstream> keyset_stream(new std::ifstream());
  keyset_stream->open(filename, std::ifstream::in);
  auto keyset_reader_result =
      crypto::tink::JsonKeysetReader::New(std::move(keyset_stream));
  if (!keyset_reader_result.ok()) {
    std::clog << "Creation of the reader failed: "
              << keyset_reader_result.status().message() << std::endl;
    exit(1);
  }
  return std::move(keyset_reader_result.ValueOrDie());
}

// Creates a KeysetHandle that for a keyset read from the given file,
// which is expected to contain a JSON-formatted keyset.
std::unique_ptr<crypto::tink::KeysetHandle> ReadKeyset(
    const std::string& filename) {
  auto keyset_reader = GetJsonKeysetReader(filename);
  auto keyset_handle_result =
      crypto::tink::CleartextKeysetHandle::Read(std::move(keyset_reader));
  if (!keyset_handle_result.ok()) {
    std::clog << "Reading the keyset failed: "
              << keyset_handle_result.status().message() << std::endl;
    exit(1);
  }
  return std::move(keyset_handle_result.ValueOrDie());
}

// Reads the specified file and returns the read content as a string.
std::string Read(const std::string& filename) {
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

// Writes the given string to the specified file.
void Write(const std::string& output, const std::string& filename) {
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

}  // namespace

int main(int argc, char** argv) {
  if (argc != 6) {
    std::clog << "Usage: " << argv[0]
         << "  keyset-file operation input-file associated-data output-file\n";
    exit(1);
  }

  std::string keyset_filename(argv[1]);
  std::string operation(argv[2]);
  std::string input_filename(argv[3]);
  std::string associated_data(argv[4]);
  std::string output_filename(argv[5]);
  if (!(operation == "encrypt" || operation == "decrypt")) {
    std::clog << "Unknown operation '" << operation << "'.\n"
              << "Expected 'encrypt' or 'decrypt'.\n";
    exit(1);
  }
  std::clog << "Using keyset from file " << keyset_filename
            << " to AEAD-" << operation
            << " file "<< input_filename
            << " with associated data '" << associated_data << "'.\n"
            << "The resulting output will be written to file "
            << output_filename << std::endl;

  // Init Tink;
  InitTink();

  // Read the keyset.
  auto keyset_handle = ReadKeyset(keyset_filename);

  // Get the primitive.
  auto primitive_result = keyset_handle->GetPrimitive<crypto::tink::Aead>();
  if (!primitive_result.ok()) {
    std::clog << "Getting AEAD-primitive from the factory failed: "
              << primitive_result.status().message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::Aead> aead =
      std::move(primitive_result.ValueOrDie());

  // Read the input.
  std::string input = Read(input_filename);

  // Compute the output.
  std::clog << operation << "ing...\n";
  std::string output;
  if (operation == "encrypt") {
    auto encrypt_result = aead->Encrypt(input, associated_data);
    if (!encrypt_result.ok()) {
      std::clog << "Error while encrypting the input:"
                << encrypt_result.status().message() << std::endl;
      exit(1);
    }
    output = encrypt_result.ValueOrDie();
  } else {  // operation == "decrypt"
    auto decrypt_result = aead->Decrypt(input, associated_data);
    if (!decrypt_result.ok()) {
      std::clog << "Error while decrypting the input:"
                << decrypt_result.status().message() << std::endl;
      exit(1);
    }
    output = decrypt_result.ValueOrDie();
  }

  // Write the output to the output file.
  Write(output, output_filename);

  std::clog << "All done.\n";
  return 0;
}
