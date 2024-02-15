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
// [START deterministic-aead-example]
// A command-line utility for testing Tink Deterministic AEAD.
#include <iostream>
#include <memory>
#include <ostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "tink/config/global_registry.h"
#include "tink/daead/deterministic_aead_config.h"
#include "tink/deterministic_aead.h"
#include "util/util.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, mode, "", "Mode of operation {encrypt|decrypt}");
ABSL_FLAG(std::string, input_filename, "", "Filename to operate on");
ABSL_FLAG(std::string, output_filename, "", "Output file name");
ABSL_FLAG(std::string, associated_data, "",
          "Associated data for Deterministic AEAD (default: empty");

namespace {

using ::crypto::tink::DeterministicAead;
using ::crypto::tink::DeterministicAeadConfig;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

constexpr absl::string_view kEncrypt = "encrypt";
constexpr absl::string_view kDecrypt = "decrypt";

void ValidateParams() {
  // [START_EXCLUDE]
  CHECK(absl::GetFlag(FLAGS_mode) == kEncrypt ||
        absl::GetFlag(FLAGS_mode) == kDecrypt)
      << "Invalid mode; must be `encrypt` or `decrypt`";
  CHECK(!absl::GetFlag(FLAGS_keyset_filename).empty())
      << "Keyset file must be specified";
  CHECK(!absl::GetFlag(FLAGS_input_filename).empty())
      << "Input file must be specified";
  CHECK(!absl::GetFlag(FLAGS_output_filename).empty())
      << "Output file must be specified";
  // [END_EXCLUDE]
}

}  // namespace

namespace tink_cc_examples {

// Deterministic AEAD example CLI implementation.
Status DeterministicAeadCli(absl::string_view mode,
                            const std::string& keyset_filename,
                            const std::string& input_filename,
                            const std::string& output_filename,
                            absl::string_view associated_data) {
  Status result = DeterministicAeadConfig::Register();
  if (!result.ok()) return result;

  // Read keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();

  // Get the primitive.
  StatusOr<std::unique_ptr<DeterministicAead>> daead =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::DeterministicAead>(
              crypto::tink::ConfigGlobalRegistry());
  if (!daead.ok()) return daead.status();

  // Read the input.
  StatusOr<std::string> input_file_content = ReadFile(input_filename);
  if (!input_file_content.ok()) return input_file_content.status();

  // Compute the output.
  std::string output;
  if (mode == kEncrypt) {
    StatusOr<std::string> result = (*daead)->EncryptDeterministically(
        *input_file_content, associated_data);
    if (!result.ok()) return result.status();
    output = *result;
  } else if (mode == kDecrypt) {
    StatusOr<std::string> result = (*daead)->DecryptDeterministically(
        *input_file_content, associated_data);
    if (!result.ok()) return result.status();
    output = *result;
  }

  // Write output to file.
  return WriteToFile(output, output_filename);
}

}  // namespace tink_cc_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string input_filename = absl::GetFlag(FLAGS_input_filename);
  std::string output_filename = absl::GetFlag(FLAGS_output_filename);
  std::string associated_data = absl::GetFlag(FLAGS_associated_data);

  std::clog << "Using keyset from file " << keyset_filename
            << " to Deterministic AEAD-" << mode << " file " << input_filename
            << " with associated data '" << associated_data << "'."
            << std::endl;
  std::clog << "The resulting output will be written to " << output_filename
            << "." << std::endl;

  CHECK_OK(tink_cc_examples::DeterministicAeadCli(
      mode, keyset_filename, input_filename, output_filename, associated_data));
  return 0;
}
// [END deterministic-aead-example]
