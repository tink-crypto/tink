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

#include "cc/cleartext_keyset_handle.h"
#include "cc/hybrid_decrypt.h"
#include "cc/keyset_handle.h"
#include "cc/hybrid/hybrid_decrypt_config.h"
#include "cc/hybrid/hybrid_decrypt_factory.h"
#include "cc/util/status.h"

using crypto::tink::HybridDecryptConfig;
using crypto::tink::HybridDecryptFactory;
using crypto::tink::CleartextKeysetHandle;
using crypto::tink::KeysetHandle;

// A command-line utility for testing HybridDecrypt-primitives.
// It requires 4 arguments:
//   keyset-file:  name of the file with the keyset to be used for decryption
//   ciphertext-file:  name of the file that contains ciphertext to be decrypted
//   context-info:  a string to be used as "context info" during the decryption
//   output-file:  name of the output file for the resulting plaintext
int main(int argc, char** argv) {
  if (argc != 5) {
    std::clog << "Usage: "
              << argv[0]
              << " keyset-file ciphertext-file context-info output-file\n";
    exit(1);
  }
  std::string keyset_filename(argv[1]);
  std::string ciphertext_filename(argv[2]);
  std::string context_info(argv[3]);
  std::string output_filename(argv[4]);
  std::clog << "Using keyset from file " << keyset_filename
            << " to decrypt file " << ciphertext_filename
            << " with context info '" << context_info << "'.\n"
            << "The resulting ciphertext will be written to file "
            << output_filename << std::endl;

  // Read the keyset.
  std::clog << "Reading the keyset...\n";
  std::ifstream keyset_stream;
  keyset_stream.open(keyset_filename, std::ifstream::in);
  auto keyset_handle_result = CleartextKeysetHandle::ParseFrom(&keyset_stream);
  if (!keyset_handle_result.ok()) {
    std::clog << "Reading the keyset failed: "
              << keyset_handle_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<KeysetHandle> keyset_handle =
      std::move(keyset_handle_result.ValueOrDie());
  keyset_stream.close();

  // Get the primitive.
  std::clog << "Initializing the factory...\n";
  auto status = HybridDecryptConfig::RegisterStandardKeyTypes();
  if (!status.ok()) {
    std::clog << "Factory initialization failed: "
              << status.error_message() << std::endl;
    exit(1);
  }
  auto primitive_result = HybridDecryptFactory::GetPrimitive(*keyset_handle);
  if (!primitive_result.ok()) {
    std::clog << "Getting HybridDecrypt-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::HybridDecrypt> hybrid_decrypt =
      std::move(primitive_result.ValueOrDie());

  // Read the ciphertext.
  std::clog << "Reading the ciphertext...\n";
  std::ifstream ciphertext_stream;
  ciphertext_stream.open(ciphertext_filename, std::ifstream::in);
  if (!ciphertext_stream.is_open()) {
    std::clog << "Error opening ciphertext file "
              << ciphertext_filename << std::endl;
    exit(1);
  }
  std::stringstream ciphertext;
  ciphertext << ciphertext_stream.rdbuf();
  ciphertext_stream.close();

  // Compute the plaintext and write it to the output file.
  std::clog << "Decrypting...\n";
  auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext.str(), context_info);
  if (!decrypt_result.ok()) {
    std::clog << "Error while decrypting the ciphertext:"
              << decrypt_result.status().error_message() << std::endl;
    exit(1);
  }
  std::clog << "Writing the plaintext...\n";
  std::ofstream output_stream(output_filename,
                              std::ofstream::out | std::ofstream::binary);
  if (!output_stream.is_open()) {
    std::clog << "Error opening output file " << output_filename << std::endl;
    exit(1);
  }
  output_stream << decrypt_result.ValueOrDie();
  output_stream.close();
  std::clog << "All done.\n";
  return 0;
}
