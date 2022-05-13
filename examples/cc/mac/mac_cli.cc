// Copyright 2022 Google LLC
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
// [START mac-example]
// A command-line utility for testing Tink MAC.

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json_keyset_reader.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/mac.h"
#include "tink/mac/mac_config.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, mode, "", "Mode of operation {compute|verify}");
ABSL_FLAG(std::string, data_filename, "", "Data file name");
ABSL_FLAG(std::string, tag_filename, "", "Authentication tag file name");

namespace {

using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::JsonKeysetReader;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::KeysetReader;
using ::crypto::tink::Mac;
using ::crypto::tink::MacConfig;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

constexpr absl::string_view kCompute = "compute";
constexpr absl::string_view kVerify = "verify";

// Creates a KeysetReader that reads a JSON-formatted keyset
// from the given file.
StatusOr<std::unique_ptr<KeysetReader>> GetJsonKeysetReader(
    const std::string& filename) {
  std::clog << "Creating a JsonKeysetReader...\n";
  auto key_input_stream = absl::make_unique<std::ifstream>();
  key_input_stream->open(filename, std::ifstream::in);
  return JsonKeysetReader::New(std::move(key_input_stream));
}

// Creates a KeysetHandle that for a keyset read from the given file,
// which is expected to contain a JSON-formatted keyset.
StatusOr<std::unique_ptr<KeysetHandle>> ReadKeyset(
    const std::string& filename) {
  StatusOr<std::unique_ptr<KeysetReader>> keyset_reader =
      GetJsonKeysetReader(filename);
  if (!keyset_reader.ok()) {
    return keyset_reader.status();
  }
  return CleartextKeysetHandle::Read(*std::move(keyset_reader));
}

// Reads `filename` and returns the read content as a string, or an error status
// if the file does not exist.
StatusOr<std::string> Read(const std::string& filename) {
  std::clog << "Reading the input...\n";
  std::ifstream input_stream;
  input_stream.open(filename, std::ifstream::in);
  if (!input_stream.is_open()) {
    return Status(absl::StatusCode::kInternal,
                  absl::StrCat("Error opening input file ", filename));
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  return input.str();
}

// Writes the given `data_to_write` to the specified file `filename`.
Status Write(const std::string& data_to_write, const std::string& filename) {
  std::clog << "Writing the output...\n";
  std::ofstream output_stream(filename,
                              std::ofstream::out | std::ofstream::binary);
  if (!output_stream.is_open()) {
    return Status(absl::StatusCode::kInternal,
                  absl::StrCat("Error opening output file ", filename));
  }
  output_stream << data_to_write;
  return crypto::tink::util::OkStatus();
}

}  // namespace

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string data_filename = absl::GetFlag(FLAGS_data_filename);
  std::string tag_filename = absl::GetFlag(FLAGS_tag_filename);

  if (mode.empty()) {
    std::cerr << "Mode must be specified with --mode=<" << kCompute << "|"
              << kVerify << ">." << std::endl;
    exit(1);
  }

  if (mode != kCompute && mode != kVerify) {
    std::cerr << "Unknown mode '" << mode << "'; "
              << "Expected either " << kCompute << " or " << kVerify << "."
              << std::endl;
    exit(1);
  }

  const std::string tag_file_action =
      (mode == kCompute) ? "written to" : "read from";
  std::clog << "Using keyset from file '" << keyset_filename << "' to " << mode
            << " authentication tag from file '" << tag_filename
            << "' for data file '" << data_filename << "'." << std::endl;
  std::clog << "The tag will be " << tag_file_action << " file '"
            << tag_filename << "'." << std::endl;

  Status result = MacConfig::Register();
  if (!result.ok()) {
    std::cerr << result.message() << std::endl;
    exit(1);
  }

  // Read the keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadKeyset(keyset_filename);
  if (!keyset_handle.ok()) {
    std::cerr << keyset_handle.status().message() << std::endl;
    exit(1);
  }

  // Get the primitive.
  StatusOr<std::unique_ptr<Mac>> mac_primitive =
      (*keyset_handle)->GetPrimitive<Mac>();
  if (!mac_primitive.ok()) {
    std::cerr << mac_primitive.status().message() << std::endl;
    exit(1);
  }

  // Read the input.
  StatusOr<std::string> data_file_content = Read(data_filename);
  if (!data_file_content.ok()) {
    std::cerr << data_file_content.status().message() << std::endl;
    exit(1);
  }

  std::string output;
  if (mode == kCompute) {
    // Compute authentication tag.
    std::clog << "Computing tag...\n";
    StatusOr<std::string> compute_result =
        (*mac_primitive)->ComputeMac(*data_file_content);
    if (!compute_result.ok()) {
      std::cerr << compute_result.status().message() << std::endl;
      exit(1);
    }
    // Write out the authentication tag to tag file.
    Status write_result = Write(*compute_result, tag_filename);
    if (!write_result.ok()) {
      std::cerr << write_result.message() << std::endl;
      exit(1);
    }
  } else {  // operation == kVerify.
    // Read the authentication tag from tag file.
    StatusOr<std::string> tag_result = Read(tag_filename);
    if (!tag_result.ok()) {
      std::cerr << tag_result.status().message() << std::endl;
      exit(1);
    }
    // Verify authentication tag.
    std::clog << "Verifying tag...\n";
    Status verify_result =
        (*mac_primitive)->VerifyMac(*tag_result, *data_file_content);
    if (!verify_result.ok()) {
      std::cerr << verify_result.message() << std::endl;
      exit(1);
    }
    std::clog << "verification succeeded" << std::endl;
  }

  std::clog << "All done." << std::endl;
  return 0;
}
// [END mac-example]
