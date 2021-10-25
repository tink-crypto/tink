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

// A command-line utility for generating Digital Signatures keys, and creating
// and verifying digital signatures.
//
// The first argument is the operation and it should be one of the following:
// gen-private-key get-public-key sign verify.
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
// sign
//   Signs the message using the given private keyset.
//   It requires 3 additional arguments:
//     private-keyset-file: name of the file with the private keyset
//     message-file: name of the file with the message
//     output-file: name of the file for the resulting output
//
// verify
//   Verifies the signature of the message using the given public keyset.
//   It requires 4 additional arguments:
//     public-keyset-file: name of the file with the public keyset
//     message-file: name of the file with the message
//     signature-file: name of the file with the signature
//     output-file: name of the file for the resulting output (valid/invalid)

#include <iostream>

#include "digital_signatures/util.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"

// Prints usage info.
void PrintUsageInfo() {
  std::clog << "Usage: operation arguments\n"
            << "where operation is one of the following:\n"
            << "  gen-private-key get-public-key sign verify\n"
            << "and, depending on the operation, arguments are:\n"
            << "  gen-private-key: output-file\n"
            << "  get-public-key: private-keyset-file output-file\n"
            << "  sign: private-keyset-file message-file output-file\n"
            << "  verify: public-keyset-file message-file signature-file "
            << "output-file" << std::endl;
}

// Generates a new private keyset using the RsaSsaPkcs13072Sha256F4 template
// and writes it to the output file.
void GeneratePrivateKey(const std::string& output_filename) {
  std::clog << "Generating a new private keyset.." << std::endl;

  auto key_template =
      crypto::tink::SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4();
  auto new_keyset_handle_result =
      crypto::tink::KeysetHandle::GenerateNew(key_template);
  if (!new_keyset_handle_result.ok()) {
    std::clog << "Generating new keyset failed: "
              << new_keyset_handle_result.status().message() << std::endl;
    exit(1);
  }
  auto keyset_handle = std::move(new_keyset_handle_result.ValueOrDie());

  std::clog << "Writing the keyset to file " << output_filename
            << "..." << std::endl;

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
              << new_keyset_handle_result.status().message() << std::endl;
    exit(1);
  }
  auto public_keyset_handle =
      std::move(new_keyset_handle_result.ValueOrDie());

  std::clog << "Writing the keyset to file " << output_filename
            << "..." << std::endl;

  Util::WriteKeyset(public_keyset_handle, output_filename);
}

// Signs the message using the given private keyset
// and writes the signature to the output file.
void Sign(const std::string& keyset_filename,
          const std::string& message_filename,
          const std::string& output_filename) {
  auto keyset_handle = Util::ReadKeyset(keyset_filename);

  auto primitive_result =
      keyset_handle->GetPrimitive<crypto::tink::PublicKeySign>();
  if (!primitive_result.ok()) {
    std::clog << "Getting PublicKeySign-primitive from the factory failed: "
              << primitive_result.status().message() << std::endl;
    exit(1);
  }
  auto public_key_sign = std::move(primitive_result.ValueOrDie());

  std::clog << "Signing message from file " << message_filename
            << " using private keyset from file " << keyset_filename
            << "..." << std::endl;

  std::string message = Util::Read(message_filename);

  auto sign_result = public_key_sign->Sign(message);
  if (!sign_result.ok()) {
    std::clog << "Error while signing the message: "
              << sign_result.status().message() << std::endl;
    exit(1);
  }
  std::string signature = sign_result.ValueOrDie();

  std::clog << "Writing the resulting signature to file " << output_filename
            << "..." << std::endl;

  Util::Write(signature, output_filename);
}

// Verifies the signature of the message using the given public keyset
// and writes the result to the output file.
void Verify(const std::string& keyset_filename,
            const std::string& message_filename,
            const std::string& signature_filename,
            const std::string& output_filename) {
  auto keyset_handle = Util::ReadKeyset(keyset_filename);

  auto primitive_result =
      keyset_handle->GetPrimitive<crypto::tink::PublicKeyVerify>();
  if (!primitive_result.ok()) {
    std::clog << "Getting PublicKeyVerify-primitive from the factory "
              << "failed: " << primitive_result.status().message() << std::endl;
    exit(1);
  }
  auto public_key_verify = std::move(primitive_result.ValueOrDie());

  std::clog << "Verifying signature from file " << signature_filename
            << " of the message from file " << message_filename
            << " using public keyset from file " << keyset_filename
            << "..." << std::endl;

  std::string signature = Util::Read(signature_filename);
  std::string message = Util::Read(message_filename);

  std::string result;
  auto verify_status = public_key_verify->Verify(signature, message);
  if (!verify_status.ok()) {
    std::clog << "Error while verifying the signature: "
              << verify_status.message() << std::endl;
    result = "invalid";
  } else {
    result = "valid";
  }

  std::clog << "Writing the result to file " << output_filename
            << "..." << std::endl;

  Util::Write(result, output_filename);
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
  } else if (operation == "sign") {
    if (argc != 5) {
      PrintUsageInfo();
      exit(1);
    }

    std::string keyset_filename = argv[2];
    std::string message_filename = argv[3];
    std::string output_filename = argv[4];

    Sign(keyset_filename, message_filename, output_filename);
  } else if (operation == "verify") {
    if (argc != 6) {
      PrintUsageInfo();
      exit(1);
    }

    std::string keyset_filename = argv[2];
    std::string message_filename = argv[3];
    std::string signature_filename = argv[4];
    std::string output_filename = argv[5];

    Verify(keyset_filename, message_filename, signature_filename,
           output_filename);
  } else {
    std::clog << "Unknown operation. Supported operations are: "
              << "gen-private-key get-public-key sign verify" << std::endl;
    exit(1);
  }

  std::clog << "Done!" << std::endl;

  return 0;
}
