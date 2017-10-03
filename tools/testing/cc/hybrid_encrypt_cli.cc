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

#include "cc/binary_keyset_reader.h"
#include "cc/cleartext_keyset_handle.h"
#include "cc/hybrid_encrypt.h"
#include "cc/keyset_handle.h"
#include "cc/hybrid/hybrid_encrypt_config.h"
#include "cc/hybrid/hybrid_encrypt_factory.h"
#include "cc/util/status.h"

using crypto::tink::BinaryKeysetReader;
using crypto::tink::CleartextKeysetHandle;
using crypto::tink::HybridEncryptConfig;
using crypto::tink::HybridEncryptFactory;
using crypto::tink::KeysetHandle;

// A command-line utility for testing HybridEncrypt-primitives.
// It requires 4 arguments:
//   keyset-file:  name of the file with the keyset to be used for encryption
//   plaintext-file:  name of the file that contains plaintext to be encrypted
//   context-info:  a string to be used as "context info" during the encryption
//   output-file:  name of the output file for the resulting ciphertext
int main(int argc, char** argv) {
  if (argc != 5) {
    std::clog << "Usage: "
              << argv[0]
              << " keyset-file plaintext-file context-info output-file\n";
    exit(1);
  }
  std::string keyset_filename(argv[1]);
  std::string plaintext_filename(argv[2]);
  std::string context_info(argv[3]);
  std::string output_filename(argv[4]);
  std::clog << "Using keyset from file " << keyset_filename
            << " to encrypt file " << plaintext_filename
            << " with context info '" << context_info << "'.\n"
            << "The resulting ciphertext will be written to file "
            << output_filename << std::endl;

  // Read the keyset.
  std::clog << "Reading the keyset...\n";
  std::unique_ptr<std::ifstream> keyset_stream(new std::ifstream());
  keyset_stream->open(keyset_filename, std::ifstream::in);
  auto keyset_reader_result = BinaryKeysetReader::New(std::move(keyset_stream));
  if (!keyset_reader_result.ok()) {
    std::clog << "Reading the keyset failed: "
              << keyset_reader_result.status().error_message() << std::endl;
    exit(1);
  }
  auto keyset_handle_result = CleartextKeysetHandle::Read(
      std::move(keyset_reader_result.ValueOrDie()));
  if (!keyset_handle_result.ok()) {
    std::clog << "Reading the keyset failed: "
              << keyset_handle_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<KeysetHandle> keyset_handle =
      std::move(keyset_handle_result.ValueOrDie());

  // Get the primitive.
  std::clog << "Initializing the factory...\n";
  auto status = HybridEncryptConfig::RegisterStandardKeyTypes();
  if (!status.ok()) {
    std::clog << "Factory initialization failed: "
              << status.error_message() << std::endl;
    exit(1);
  }
  auto primitive_result = HybridEncryptFactory::GetPrimitive(*keyset_handle);
  if (!primitive_result.ok()) {
    std::clog << "Getting HybridEncrypt-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::HybridEncrypt> hybrid_encrypt =
      std::move(primitive_result.ValueOrDie());

  // Read the plaintext.
  std::clog << "Reading the plaintext...\n";
  std::ifstream plaintext_stream;
  plaintext_stream.open(plaintext_filename, std::ifstream::in);
  if (!plaintext_stream.is_open()) {
    std::clog << "Error opening plaintext file "
              << plaintext_filename << std::endl;
    exit(1);
  }
  std::stringstream plaintext;
  plaintext << plaintext_stream.rdbuf();
  plaintext_stream.close();

  // Compute the ciphertext and write it to the output file.
  std::clog << "Encrypting...\n";
  auto encrypt_result = hybrid_encrypt->Encrypt(plaintext.str(), context_info);
  if (!encrypt_result.ok()) {
    std::clog << "Error while encrypting the plaintext:"
              << encrypt_result.status().error_message() << std::endl;
    exit(1);
  }
  std::clog << "Writing the ciphertext...\n";
  std::ofstream output_stream(output_filename,
                              std::ofstream::out | std::ofstream::binary);
  if (!output_stream.is_open()) {
    std::clog << "Error opening output file " << output_filename << std::endl;
    exit(1);
  }
  output_stream << encrypt_result.ValueOrDie();
  output_stream.close();
  std::clog << "All done.\n";
  return 0;
}
