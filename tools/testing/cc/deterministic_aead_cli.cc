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

#include <iostream>
#include <fstream>

#include "tink/deterministic_aead.h"
#include "tink/keyset_handle.h"
#include "tink/daead/deterministic_aead_factory.h"
#include "tink/util/status.h"
#include "tools/testing/cc/cli_util.h"

using crypto::tink::DeterministicAeadFactory;
using crypto::tink::KeysetHandle;

// A command-line utility for testing DeterministicAead-primitives.
// It requires 5 arguments:
//   keyset-file:  name of the file with the keyset to be used for encryption
//   operation: the actual DeterminisiticAead-operation, i.e.
//       "encrypt_deterministically" or "decrypt_deterministically"
//   input-file:  name of the file with input (plaintext for encryption, or
//       or ciphertext for decryption)
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
  if (!(operation == "encryptdeterministically" ||
        operation == "decryptdeterministically")) {
    std::clog << "Unknown operation '" << operation << "'.\n"
              << "Expected 'encryptdeterministically' "
              << "or 'decryptdeterministically'.\n";
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
  auto primitive_result =
      DeterministicAeadFactory::GetPrimitive(*keyset_handle);
  if (!primitive_result.ok()) {
    std::clog << "Getting DeterministicAead-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::DeterministicAead> daead =
      std::move(primitive_result.ValueOrDie());

  // Read the input.
  std::string input = CliUtil::Read(input_filename);
  std::string associated_data = CliUtil::Read(associated_data_file);

  // Compute the output.
  std::clog << "performing operation " << operation << "...\n";
  std::string output;
  if (operation == "encryptdeterministically") {
    auto encrypt_result = daead->EncryptDeterministically(input,
                                                          associated_data);
    if (!encrypt_result.ok()) {
      std::clog << "Error while encrypting the input:"
                << encrypt_result.status().error_message() << std::endl;
      exit(1);
    }
    output = encrypt_result.ValueOrDie();
  } else {  // operation == "decryptdeterministically"
    auto decrypt_result = daead->DecryptDeterministically(input,
                                                         associated_data);
    if (!decrypt_result.ok()) {
      std::clog << "Error while decrypting the input:"
                << decrypt_result.status().error_message() << std::endl;
      exit(1);
    }
    output = decrypt_result.ValueOrDie();
  }

  // Write the output to the output file.
  CliUtil::Write(output, output_filename);

  std::clog << "All done.\n";
  return 0;
}
