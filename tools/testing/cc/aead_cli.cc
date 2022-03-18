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

#include <fstream>
#include <iostream>
#include <string>
#include <utility>

#include "tink/aead.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "testing/cc/cli_util.h"

using crypto::tink::KeysetHandle;

// A command-line utility for testing AEAD-primitives.
// It requires 5 arguments:
//   keyset-file:  name of the file with the keyset to be used for encryption
//   operation: the actual AEAD-operation, i.e. "encrypt" or "decrypt"
//   input-file:  name of the file with input (plaintext for encryption, or
//                or ciphertext for decryption)
//   associated-data-file:  name of the file containing associated data
//   output-file:  name of the file for the resulting output
int main(int argc, char** argv) {
  if (argc != 6) {
    std::clog << "Usage: " << argv[0]
         << " keyset-file operation input-file associated-data-file "
         << "output-file\n";
    exit(1);
  }
  std::string keyset_filename(argv[1]);
  std::string operation(argv[2]);
  std::string input_filename(argv[3]);
  std::string associated_data_file(argv[4]);
  std::string output_filename(argv[5]);
  if (!(operation == "encrypt" || operation == "decrypt")) {
    std::clog << "Unknown operation '" << operation << "'.\n"
              << "Expected 'encrypt' or 'decrypt'.\n";
    exit(1);
  }
  std::clog << "Using keyset from file " << keyset_filename
            << " to AEAD-" << operation
            << " file "<< input_filename
            << " with associated data from from file " << associated_data_file
            << ".\n" << "The resulting output will be written to file "
            << output_filename << std::endl;

  // Init Tink;
  CliUtil::InitTink();

  // Read the keyset.
  std::unique_ptr<KeysetHandle> keyset_handle =
      CliUtil::ReadKeyset(keyset_filename);

  // Get the primitive.
  auto primitive_result = keyset_handle->GetPrimitive<crypto::tink::Aead>();
  if (!primitive_result.ok()) {
    std::clog << "Getting AEAD-primitive from the factory failed: "
              << primitive_result.status().message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::Aead> aead =
      std::move(primitive_result.value());

  // Read the input.
  std::string input = CliUtil::Read(input_filename);
  std::string associated_data = CliUtil::Read(associated_data_file);

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
    output = encrypt_result.value();
  } else {  // operation == "decrypt"
    auto decrypt_result = aead->Decrypt(input, associated_data);
    if (!decrypt_result.ok()) {
      std::clog << "Error while decrypting the input:"
                << decrypt_result.status().message() << std::endl;
      exit(1);
    }
    output = decrypt_result.value();
  }

  // Write the output to the output file.
  CliUtil::Write(output, output_filename);

  std::clog << "All done.\n";
  return 0;
}
