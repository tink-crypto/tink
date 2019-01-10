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

#include "tink/public_key_sign.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tools/testing/cc/cli_util.h"

using crypto::tink::KeysetHandle;

// A command-line utility for testing PublicKeySign-primitives.
// It requires 3 arguments:
//   keyset-file:  name of the file with the keyset to be used for signing
//   message-file:  name of the file that contains message to be signed
//   output-file:  name of the output file for the resulting plaintext
int main(int argc, char** argv) {
  if (argc != 4) {
    std::clog << "Usage: "
              << argv[0]
              << " keyset-file message-file output-file\n";
    exit(1);
  }
  std::string keyset_filename(argv[1]);
  std::string message_filename(argv[2]);
  std::string output_filename(argv[3]);
  std::clog << "Using keyset from file " << keyset_filename
            << " to sign message from " << message_filename << ".\n"
            << "The resulting signature will be written to file "
            << output_filename << std::endl;

  // Init Tink;
  CliUtil::InitTink();

  // Read the keyset.
  std::unique_ptr<KeysetHandle> keyset_handle =
      CliUtil::ReadKeyset(keyset_filename);

  // Get the primitive.
  auto primitive_result =
      keyset_handle->GetPrimitive<crypto::tink::PublicKeySign>();
  if (!primitive_result.ok()) {
    std::clog << "Getting PublicKeySign-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::PublicKeySign> public_key_sign =
      std::move(primitive_result.ValueOrDie());

  // Read the message.
  std::string message = CliUtil::Read(message_filename);

  // Compute the signature.
  std::clog << "Signing...\n";
  auto sign_result = public_key_sign->Sign(message);
  if (!sign_result.ok()) {
    std::clog << "Error while signin the message:"
              << sign_result.status().error_message() << std::endl;
    exit(1);
  }

  // Write the signature to the output file.
  CliUtil::Write(sign_result.ValueOrDie(), output_filename);

  std::clog << "All done.\n";
  return 0;
}
