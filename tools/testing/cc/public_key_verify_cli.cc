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

#include "tink/public_key_verify.h"
#include "tink/keyset_handle.h"
#include "tink/signature/public_key_verify_factory.h"
#include "tink/util/status.h"
#include "testing/cc/cli_util.h"

using crypto::tink::KeysetHandle;

// A command-line utility for testing PublicKeyVerify-primitives.
// It requires 4 arguments:
//   keyset-file:  name of the file with the keyset to be used for verification
//   signature-file:  name of the file that contains the signature
//   message-file:  name of the file that contains message that was signed
//   output-file:  name of the output file for the verfication result
//                 (valid/invalid)
int main(int argc, char** argv) {
  if (argc != 5) {
    std::clog << "Usage: "
              << argv[0]
              << " keyset-file signature-file message-file output-file\n";
    exit(1);
  }
  std::string keyset_filename(argv[1]);
  std::string signature_filename(argv[2]);
  std::string message_filename(argv[3]);
  std::string output_filename(argv[4]);
  std::clog << "Using keyset from file " << keyset_filename
            << " to verify signature from file " << signature_filename
            << " of the message from file " << message_filename << ".\n"
            << "The verification result will be written to file "
            << output_filename << std::endl;

  // Init Tink;
  CliUtil::InitTink();

  // Read the keyset.
  std::unique_ptr<KeysetHandle> keyset_handle =
      CliUtil::ReadKeyset(keyset_filename);

  // Get the primitive.
  auto primitive_result =
      keyset_handle->GetPrimitive<crypto::tink::PublicKeyVerify>();
  if (!primitive_result.ok()) {
    std::clog << "Getting PublicKeyVerify-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::PublicKeyVerify> public_key_verify =
      std::move(primitive_result.ValueOrDie());

  // Read the signature.
  std::string signature = CliUtil::Read(signature_filename);

  // Read the message.
  std::string message = CliUtil::Read(message_filename);

  // Verify the signature.
  std::clog << "Verifying...\n";
  std::string result = "valid";
  auto status = public_key_verify->Verify(signature, message);
  if (!status.ok()) {
    std::clog << "Error while verifying the signature:"
              << status.error_message() << std::endl;
    result = "invalid";
  }

  // Write the verification result to the output file.
  CliUtil::Write(result, output_filename);

  std::clog << "All done.\n";
  return 0;
}
