// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////


#include <string>
#include <vector>

#include "absl/strings/ascii.h"
#include "tink/aead.h"
#include "tink/integration/gcpkms/gcp_kms_client.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "testing/cc/cli_util.h"

using crypto::tink::Aead;
using crypto::tink::integration::gcpkms::GcpKmsClient;

// A command-line utility for testing GcpKmsAead.
// It requires 6 arguments:
//   key-name-file:  Google Cloud KMS key to be used for encryption
//   credentials-file: credentials file containing GCP credentials
//   operation: the actual AEAD-operation, i.e. "encrypt" or "decrypt"
//   input-file:  name of the file with input (plaintext for encryption, or
//                or ciphertext for decryption)
//   associated-data:  a string to be used as associated data
//   output-file:  name of the file for the resulting output
int main(int argc, char** argv) {
  if (argc != 7) {
    std::clog << "Usage: " << argv[0]
              << " key-name-file credentials-file"
              << " operation input-file associated-data output-file\n";
    exit(1);
  }
  std::string key_name_filename(argv[1]);
  std::string credentials_filename(argv[2]);
  std::string operation(argv[3]);
  std::string input_filename(argv[4]);
  std::string associated_data(argv[5]);
  std::string output_filename(argv[6]);
  if (!(operation == "encrypt" || operation == "decrypt")) {
    std::clog << "Unknown operation '" << operation << "'.\n"
              << "Expected 'encrypt' or 'decrypt'.\n";
    exit(1);
  }
  std::clog << "Using key_name from file " << key_name_filename
            << " and GCP credentials from file " << credentials_filename
            << " to AEAD-" << operation
            << " file "<< input_filename
            << " with associated data '" << associated_data << "'.\n"
            << "The resulting output will be written to file "
            << output_filename << std::endl;

  std::string key_name = CliUtil::Read(key_name_filename);
  absl::StripAsciiWhitespace(&key_name);
  std::clog << "Will use key name " << key_name << std::endl;

  // Create GcpKmsClient.
  auto client_result = GcpKmsClient::New("", credentials_filename);
  if (!client_result.ok()) {
    std::clog << "Aead creation failed: "
              << client_result.status().message()
              << "\n";
    exit(1);
  }
  auto client = std::move(client_result.ValueOrDie());

  // Create Aead-primitive.
  auto aead_result = client->GetAead("gcp-kms://" + key_name);
  if (!aead_result.ok()) {
    std::clog << "Aead creation failed: "
              << aead_result.status().message()
              << "\n";
    exit(1);
  }
  std::unique_ptr<Aead> aead(std::move(aead_result.ValueOrDie()));

  // Read the input.
  std::string input = CliUtil::Read(input_filename);

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
  CliUtil::Write(output, output_filename);

  std::clog << "All done.\n";
}
