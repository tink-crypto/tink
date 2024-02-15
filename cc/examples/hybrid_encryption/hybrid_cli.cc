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
// [START hybrid-example]
// A command-line utility for testing Tink Hybrid Encryption.
#include <iostream>
#include <memory>
#include <ostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "tink/config/global_registry.h"
#include "util/util.h"
#ifndef TINK_EXAMPLES_EXCLUDE_HPKE
#include "tink/hybrid/hpke_config.h"
#endif
#include "tink/hybrid/hybrid_config.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, mode, "", "Mode of operation {encrypt|decrypt}");
ABSL_FLAG(std::string, input_filename, "", "Input file name");
ABSL_FLAG(std::string, output_filename, "", "Output file name");
ABSL_FLAG(std::string, context_info, "",
          "Context info for Hybrid Encryption/Decryption");

namespace {

using ::crypto::tink::HybridDecrypt;
using ::crypto::tink::HybridEncrypt;
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

Status HybridCli(absl::string_view mode, const std::string& keyset_filename,
                 const std::string& input_filename,
                 const std::string& output_filename,
                 absl::string_view context_info) {
  Status result = crypto::tink::HybridConfig::Register();
  if (!result.ok()) return result;
#ifndef TINK_EXAMPLES_EXCLUDE_HPKE
  // HPKE isn't supported when using OpenSSL as a backend.
  result = crypto::tink::RegisterHpke();
  if (!result.ok()) return result;
#endif

  // Read the keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();

  // Read the input.
  StatusOr<std::string> input_file_content = ReadFile(input_filename);
  if (!input_file_content.ok()) return input_file_content.status();

  // Compute the output.
  std::string output;
  if (mode == kEncrypt) {
    // Get the hybrid encryption primitive.
    StatusOr<std::unique_ptr<HybridEncrypt>> hybrid_encrypt_primitive =
        (*keyset_handle)
            ->GetPrimitive<crypto::tink::HybridEncrypt>(
                crypto::tink::ConfigGlobalRegistry());
    if (!hybrid_encrypt_primitive.ok()) {
      return hybrid_encrypt_primitive.status();
    }
    // Generate the ciphertext.
    StatusOr<std::string> encrypt_result =
        (*hybrid_encrypt_primitive)->Encrypt(*input_file_content, context_info);
    if (!encrypt_result.ok()) return encrypt_result.status();
    output = encrypt_result.value();
  } else {  // operation == kDecrypt.
    // Get the hybrid decryption primitive.
    StatusOr<std::unique_ptr<HybridDecrypt>> hybrid_decrypt_primitive =
        (*keyset_handle)
            ->GetPrimitive<crypto::tink::HybridDecrypt>(
                crypto::tink::ConfigGlobalRegistry());
    if (!hybrid_decrypt_primitive.ok()) {
      return hybrid_decrypt_primitive.status();
    }
    // Recover the plaintext.
    StatusOr<std::string> decrypt_result =
        (*hybrid_decrypt_primitive)->Decrypt(*input_file_content, context_info);
    if (!decrypt_result.ok()) return decrypt_result.status();
    output = decrypt_result.value();
  }

  // Write the output to the output file.
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
  std::string context_info = absl::GetFlag(FLAGS_context_info);

  std::clog << "Using keyset from file " << keyset_filename << " to hybrid "
            << mode << " file " << input_filename << " with context info '"
            << context_info << "'." << '\n';
  std::clog << "The resulting output will be written to " << output_filename
            << '\n';

  CHECK_OK(tink_cc_examples::HybridCli(mode, keyset_filename, input_filename,
                                       output_filename, context_info));
  return 0;
}
// [END hybrid-example]
