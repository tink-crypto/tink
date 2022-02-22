// Copyright 2018 Google LLC
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
#include "aws/core/Aws.h"
#include "aws/core/utils/crypto/Factories.h"
#include "aws/core/utils/memory/AWSMemory.h"
#include "aws/kms/KMSClient.h"
#include "tink/aead.h"
#include "tink/integration/awskms/aws_crypto.h"
#include "tink/integration/awskms/aws_kms_aead.h"
#include "tink/integration/awskms/aws_kms_client.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "testing/cc/cli_util.h"

using crypto::tink::Aead;
using crypto::tink::integration::awskms::AwsKmsAead;
using crypto::tink::integration::awskms::AwsKmsClient;

// A command-line utility for testing AwsKmsAead.
// It requires 6 arguments:
//   key-arn-file:  Amazon Resource Name of AWS KMS key for encryption
//   credentials-file: credentials file containing AWS access key
//   operation: the actual AEAD-operation, i.e. "encrypt" or "decrypt"
//   input-file:  name of the file with input (plaintext for encryption, or
//                or ciphertext for decryption)
//   associated-data:  a string to be used as associated data
//   output-file:  name of the file for the resulting output
int main(int argc, char** argv) {
  if (argc != 7) {
    std::clog << "Usage: " << argv[0]
              << " key-arn-file credentials-file"
              << " operation input-file associated-data output-file\n";
    exit(1);
  }
  std::string key_arn_filename(argv[1]);
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
  std::clog << "Using key_arn from file " << key_arn_filename
            << " and AWS credentials from file " << credentials_filename
            << " to AEAD-" << operation
            << " file "<< input_filename
            << " with associated data '" << associated_data << "'.\n"
            << "The resulting output will be written to file "
            << output_filename << std::endl;

  std::string key_arn = CliUtil::Read(key_arn_filename);
  absl::StripAsciiWhitespace(&key_arn);
  std::clog << "Will use key ARN " << key_arn << std::endl;

  // Create AwsKmsClient.
  auto client_result = AwsKmsClient::New("", credentials_filename);
  if (!client_result.ok()) {
    std::clog << "Aead creation failed: "
              << client_result.status().message()
              << "\n";
    exit(1);
  }
  auto client = std::move(client_result.ValueOrDie());

  // Create Aead-primitive.
  auto aead_result = client->GetAead("aws-kms://" + key_arn);
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
