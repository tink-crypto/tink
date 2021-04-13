// Copyright 2020 Google LLC
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

// A command-line utility for generating Hybrid Encryption keys, and encrypting
// and decrypting files using hybrid encryption.
//
// The first argument is the operation and it should be one of the following:
// gen-private-key get-public-key encrypt decrypt.
// Additional arguments depend on the operation.
//
// gen-private-key
//   Generates a new private keyset using the RsaSsaPkcs13072Sha256F4 template.
//   It requires 1 additional argument:
//     output-file: name of the file for the resulting output
//
// get-public-key
//   Extracts a public keyset associated with the given private keyset.
//   It requires 2 additional arguments:
//     private-keyset-file: name of the file with the private keyset
//     output-file: name of the file for the resulting output
//
// encrypt
//   Encrypts the message using the given public keyset.
//   It requires 4 additional arguments:
//     public-keyset-file: name of the file with the public keyset
//     message-file: name of the file with the message
//     context-info-file: name of the file with the context-info,
//                        can also be an empty file
//     output-file: name of the file for the resulting output
//
// decrypt
//   Decrypts the encrypted message using the given private keyset.
//   It requires 4 additional arguments:
//     private-keyset-file: name of the file with the private keyset
//     encrypted-message-file: name of the file with the message
//     context-info-file: name of the file with the context-info
//     output-file: name of the file for the decrypted message

#include <iostream>

#include "tink/hybrid/hybrid_key_templates.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "hybrid_encryption/util.h"

// Prints usage info.
void PrintUsageInfo() {
  std::clog << "Usage: operation arguments\n"
            << "where operation is one of the following:\n"
            << "  gen-private-key get-public-key encrypt decrypt\n"
            << "and, depending on the operation, arguments are:\n"
            << "  gen-private-key: output-file\n"
            << "  get-public-key: private-keyset-file output-file\n"
            << "  encrypt: public-keyset-file message-file context-info-file"
            << " output-file\n"
            << "  decrypt: private-keyset-file encrypted-file context-info-file"
            << " output-file"
            << std::endl;
}

// Generates a new private keyset using the EciesP256HkdfHmacSha256Aes128Gcm
// template and writes it to the output file.
void GeneratePrivateKey(const std::string& output_filename) {
  std::clog << "Generating a new private keyset.." << std::endl;

  auto key_template =
      crypto::tink::HybridKeyTemplates::EciesP256HkdfHmacSha256Aes128Gcm();
  auto new_keyset_handle_result =
      crypto::tink::KeysetHandle::GenerateNew(key_template);
  if (!new_keyset_handle_result.ok()) {
    std::clog << "Generating new keyset failed: "
              << new_keyset_handle_result.status().error_message() << std::endl;
    exit(1);
  }
  auto keyset_handle = std::move(new_keyset_handle_result.ValueOrDie());

  std::clog << "Writing the keyset to file " << output_filename << "..."
            << std::endl;

  Util::WriteKeyset(keyset_handle, output_filename);
}

// Extracts a public keyset associated with the given private keyset
// and writes it to the output file.
void ExtractPublicKey(const std::string& private_keyset_filename,
                      const std::string& output_filename) {
  std::clog << "Extracting a public keyset associated with the private "
            << "keyset from file " << private_keyset_filename << "..."
            << std::endl;

  auto private_keyset_handle = Util::ReadKeyset(private_keyset_filename);

  auto new_keyset_handle_result =
      private_keyset_handle->GetPublicKeysetHandle();
  if (!new_keyset_handle_result.ok()) {
    std::clog << "Getting the keyset failed: "
              << new_keyset_handle_result.status().error_message() << std::endl;
    exit(1);
  }
  auto public_keyset_handle = std::move(new_keyset_handle_result.ValueOrDie());

  std::clog << "Writing the keyset to file " << output_filename << "..."
            << std::endl;

  Util::WriteKeyset(public_keyset_handle, output_filename);
}

// Encrypts the message using the given public keyset
// and writes the encrypted message to the output file.
void Encrypt(const std::string& keyset_filename,
             const std::string& message_filename,
             const std::string& context_info_filename,
             const std::string& output_filename) {
  auto keyset_handle = Util::ReadKeyset(keyset_filename);

  auto primitive_result =
      keyset_handle->GetPrimitive<crypto::tink::HybridEncrypt>();
  if (!primitive_result.ok()) {
    std::clog << "Getting HybridEncryption-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  auto hybrid_encrypt = std::move(primitive_result.ValueOrDie());

  std::clog << "Encrypting message from file " << message_filename
            << " using public keyset from file " << keyset_filename << "..."
            << std::endl;

  std::string message = Util::Read(message_filename);
  std::string context_info = Util::Read(context_info_filename);

  auto encrypt_result = hybrid_encrypt->Encrypt(message, context_info);
  if (!encrypt_result.ok()) {
    std::clog << "Error while encrypting the message: "
              << encrypt_result.status().error_message() << std::endl;
    exit(1);
  }
  std::string encrypted_message = encrypt_result.ValueOrDie();

  std::clog << "Writing the resulting encrypted message to file "
            << output_filename << "..." << std::endl;

  Util::Write(encrypted_message, output_filename);
}

// Decrypts the encrypted message using the given private keyset
// and writes the result to the output file.
void Decrypt(const std::string& keyset_filename,
             const std::string& message_filename,
             const std::string& context_info_filename,
             const std::string& output_filename) {
  auto keyset_handle = Util::ReadKeyset(keyset_filename);

  auto primitive_result =
      keyset_handle->GetPrimitive<crypto::tink::HybridDecrypt>();
  if (!primitive_result.ok()) {
    std::clog << "Getting HybridDecrypt-primitive from the factory "
              << "failed: " << primitive_result.status().error_message()
              << std::endl;
    exit(1);
  }
  auto hybrid_decrypt = std::move(primitive_result.ValueOrDie());

  std::clog << "Decrypting the encrypted file " << message_filename
            << " to the file " << output_filename
            << " using private keyset from file " << keyset_filename << "..."
            << std::endl;

  std::string message = Util::Read(message_filename);
  std::string context_info = Util::Read(context_info_filename);

  std::string result;
  auto decrypt_status = hybrid_decrypt->Decrypt(message, context_info);
  if (!decrypt_status.ok()) {
    std::clog << "Error while decrypting the file: "
              << decrypt_status.status().error_message() << std::endl;
    exit(1);
  }

  std::string decrypted_message = decrypt_status.ValueOrDie();

  std::clog << "Writing the resulting decrypted message to file "
            << output_filename << "..." << std::endl;

  Util::Write(decrypted_message, output_filename);
}

int main(int argc, char** argv) {
  if (argc == 1) {
    PrintUsageInfo();
    exit(1);
  }

  Util::InitTink();

  std::string operation = argv[1];

  if (operation == "gen-private-key") {
    if (argc != 3) {
      PrintUsageInfo();
      exit(1);
    }

    std::string output_filename = argv[2];

    GeneratePrivateKey(output_filename);
  } else if (operation == "get-public-key") {
    if (argc != 4) {
      PrintUsageInfo();
      exit(1);
    }

    std::string private_keyset_filename = argv[2];
    std::string output_filename = argv[3];

    ExtractPublicKey(private_keyset_filename, output_filename);
  } else if (operation == "encrypt") {
    if (argc != 6) {
      PrintUsageInfo();
      exit(1);
    }

    std::string keyset_filename = argv[2];
    std::string message_filename = argv[3];
    std::string context_info_filename = argv[4];
    std::string output_filename = argv[5];

    Encrypt(keyset_filename, message_filename, context_info_filename,
            output_filename);
  } else if (operation == "decrypt") {
    if (argc != 6) {
      PrintUsageInfo();
      exit(1);
    }

    std::string keyset_filename = argv[2];
    std::string message_filename = argv[3];
    std::string context_info_filename = argv[4];
    std::string output_filename = argv[5];

    Decrypt(keyset_filename, message_filename, context_info_filename,
            output_filename);
  } else {
    std::clog << "Unknown operation. Supported operations are: "
              << "gen-private-key get-public-key encrypt decrypt" << std::endl;
    exit(1);
  }

  std::clog << "Done!" << std::endl;

  return 0;
}
