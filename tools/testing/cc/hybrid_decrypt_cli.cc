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

#include "tink/hybrid_decrypt.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tools/testing/cc/cli_util.h"

using crypto::tink::KeysetHandle;

// A command-line utility for testing HybridDecrypt-primitives.
// It requires 4 arguments:
//   keyset-file:  name of the file with the keyset to be used for decryption
//   ciphertext-file:  name of the file that contains ciphertext to be decrypted
//   context-info-file:  name of the file that contains "context info" which
//       will be used during the decryption
//   output-file:  name of the output file for the resulting plaintext
int main(int argc, char** argv) {
  if (argc != 5) {
    std::clog << "Usage: "
              << argv[0]
              << " keyset-file ciphertext-file context-info-file output-file\n";
    exit(1);
  }
  std::string keyset_filename(argv[1]);
  std::string ciphertext_filename(argv[2]);
  std::string context_info_filename(argv[3]);
  std::string output_filename(argv[4]);
  std::clog << "Using keyset from file " << keyset_filename
            << " to decrypt file " << ciphertext_filename
            << " with context info from file " << context_info_filename
            << ".\n" << "The resulting ciphertext will be written to file "
            << output_filename << std::endl;

  // Init Tink;
  CliUtil::InitTink();

  // Read the keyset.
  std::unique_ptr<KeysetHandle> keyset_handle =
      CliUtil::ReadKeyset(keyset_filename);

  // Get the primitive.
  auto primitive_result =
      keyset_handle->GetPrimitive<crypto::tink::HybridDecrypt>();
  if (!primitive_result.ok()) {
    std::clog << "Getting HybridDecrypt-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::HybridDecrypt> hybrid_decrypt =
      std::move(primitive_result.ValueOrDie());

  // Read the ciphertext.
  std::string ciphertext = CliUtil::Read(ciphertext_filename);
  std::string context_info = CliUtil::Read(context_info_filename);

  // Compute the plaintext.
  std::clog << "Decrypting...\n";
  auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
  if (!decrypt_result.ok()) {
    std::clog << "Error while decrypting the ciphertext:"
              << decrypt_result.status().error_message() << std::endl;
    exit(1);
  }

  // Write the plaintext to the output file.
  CliUtil::Write(decrypt_result.ValueOrDie(), output_filename);

  std::clog << "All done.\n";
  return 0;
}
