// Copyright 2018 Google Inc.
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

#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/util/status.h"
#include "tools/testing/cc/cli_util.h"

using crypto::tink::KeysetReader;
using crypto::tink::KeysetWriter;

// A command-line utility for testing KeysetReader & KeysetWriter interfaces.
// It reads a keyset from the given input file, and writes it to the specified
// output file.  It requires 4 arguments:
//   input-format:  "JSON" or "BINARY".
//   input-keyset-file:  name of the input file containing the keyset to be read
//   output-format:  "JSON" or "BINARY".
//   input-keyset-file:  name of the output file
int main(int argc, char** argv) {
  if (argc != 5) {
    std::clog << "Usage: " << argv[0]
        << " input-format input-keyset-file output-format output-keyset-file"
        << "\n";
    exit(1);
  }
  std::string input_format(argv[1]);
  std::string input_keyset_filename(argv[2]);
  std::string output_format(argv[3]);
  std::string output_keyset_filename(argv[4]);

  std::clog << "Reading keyset from file " << input_keyset_filename
            << " in format " << input_format
            << " and writing to file " << output_keyset_filename
            << " in format " << output_format << ". " << std::endl;

  std::unique_ptr<KeysetReader> keyset_reader;
  if (input_format == "JSON") {
    keyset_reader = CliUtil::GetJsonKeysetReader(input_keyset_filename);
  } else if (input_format == "BINARY") {
    keyset_reader = CliUtil::GetBinaryKeysetReader(input_keyset_filename);
  } else {
    std::clog << "Unknown input format: '" << input_format << "'.\n"
              << "Expected 'JSON' or 'BINARY'.\n";
    exit(1);
  }
  std::unique_ptr<KeysetWriter> keyset_writer;
  if (output_format == "JSON") {
    keyset_writer = CliUtil::GetJsonKeysetWriter(output_keyset_filename);
  } else if (output_format == "BINARY") {
    keyset_writer = CliUtil::GetBinaryKeysetWriter(output_keyset_filename);
  } else {
    std::clog << "Unknown output format: '" << input_format << "'.\n"
              << "Expected 'JSON' or 'BINARY'.\n";
    exit(1);
  }

  auto keyset_result = keyset_reader->Read();
  if (!keyset_result.ok()) {
    std::clog << "Reading of the keyset failed: " << keyset_result.status()
              << std::endl;
    exit(1);
  }
  auto status = keyset_writer->Write(*(keyset_result.ValueOrDie()));
  if (!status.ok()) {
    std::clog << "Writing of the keyset failed: " << status << std::endl;
    exit(1);
  }

  std::clog << "All done.\n";
  return 0;
}
