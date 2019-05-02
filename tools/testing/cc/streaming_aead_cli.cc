// Copyright 2019 Google Inc.
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

#include "tink/streaming_aead.h"
#include "tink/keyset_handle.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tools/testing/cc/cli_util.h"

using crypto::tink::InputStream;
using crypto::tink::KeysetHandle;
using crypto::tink::OutputStream;
using crypto::tink::util::IstreamInputStream;
using crypto::tink::util::OstreamOutputStream;

// A command-line utility for testing StreamingAead-primitives.
// It requires 5 arguments:
//   keyset-file:  name of the file with the keyset to be used for encryption
//   operation: the actual StreamingAead-operation, i.e. "encrypt" or "decrypt"
//   input-file:  name of the file with input (plaintext for encryption, or
//                or ciphertext for decryption)
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
  if (!(operation == "encrypt" || operation == "decrypt")) {
    std::clog << "Unknown operation '" << operation << "'.\n"
              << "Expected 'encrypt' or 'decrypt'.\n";
    exit(1);
  }
  std::clog << "Using keyset from file " << keyset_filename
            << " to StreamingAead-" << operation
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
      keyset_handle->GetPrimitive<crypto::tink::StreamingAead>();
  if (!primitive_result.ok()) {
    std::clog << "Getting StreamingAead-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::StreamingAead> saead =
      std::move(primitive_result.ValueOrDie());

  // Open input/output streams, and read the associated data.
  auto input = absl::make_unique<std::ifstream>(
      input_filename, std::ifstream::in | std::ifstream::binary);
  std::unique_ptr<InputStream> input_stream(
      absl::make_unique<IstreamInputStream>(std::move(input)));
  auto output = absl::make_unique<std::ofstream>(
      output_filename, std::ofstream::out | std::ofstream::binary);
  std::unique_ptr<OutputStream> output_stream(
      absl::make_unique<OstreamOutputStream>(std::move(output)));
  std::string associated_data = CliUtil::Read(associated_data_file);

  // Compute the output.
  std::clog << operation << "ing...\n";
  if (operation == "encrypt") {
    // Turn output_stream into an encrypting stream.
    auto enc_stream_result =
        saead->NewEncryptingStream(std::move(output_stream), associated_data);
    if (!enc_stream_result.ok()) {
      std::clog << "Error while creating an encrypting stream:"
                << enc_stream_result.status().error_message() << std::endl;
      exit(1);
    }
    output_stream = std::move(enc_stream_result.ValueOrDie());
  } else {  // operation == "decrypt"
    // Turn input_stream into a decrypting stream.
    auto dec_stream_result =
        saead->NewDecryptingStream(std::move(input_stream), associated_data);
    if (!dec_stream_result.ok()) {
      std::clog << "Error while creating a decrypting stream:"
                << dec_stream_result.status().error_message() << std::endl;
      exit(1);
    }
    input_stream = std::move(dec_stream_result.ValueOrDie());
  }
  CliUtil::CopyStream(input_stream.get(), output_stream.get());
  std::clog << "All done.\n";
  return 0;
}
