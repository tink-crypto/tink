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
// A command-line utility for showcasing using the Tink MAC primitive.

#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "util/util.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/mac_config.h"
#include "tink/util/status.h"

ABSL_FLAG(std::string, keyset_filename, "", "Keyset file in JSON format");
ABSL_FLAG(std::string, mode, "", "Mode of operation {compute|verify}");
ABSL_FLAG(std::string, data_filename, "", "Data file name");
ABSL_FLAG(std::string, tag_filename, "", "Authentication tag file name");

namespace {

using ::crypto::tink::KeysetHandle;
using ::crypto::tink::Mac;
using ::crypto::tink::MacConfig;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;

constexpr absl::string_view kCompute = "compute";
constexpr absl::string_view kVerify = "verify";

void ValidateParams() {
  // [START_EXCLUDE]
  CHECK(absl::GetFlag(FLAGS_mode) == kCompute ||
        absl::GetFlag(FLAGS_mode) == kVerify)
      << "Invalid mode; must be `" << kCompute << "` or `" << kVerify << "`";
  CHECK(!absl::GetFlag(FLAGS_keyset_filename).empty())
      << "Keyset file must be specified";
  CHECK(!absl::GetFlag(FLAGS_data_filename).empty())
      << "Data file must be specified";
  CHECK(!absl::GetFlag(FLAGS_tag_filename).empty())
      << "Tag file must be specified";
  // [END_EXCLUDE]
}

}  // namespace

namespace tink_cc_examples {

// MAC example CLI implementation.
Status MacCli(absl::string_view mode, const std::string keyset_filename,
              const std::string& data_filename,
              const std::string& tag_filename) {
  Status result = MacConfig::Register();
  if (!result.ok()) return result;

  // Read the keyset from file.
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      ReadJsonCleartextKeyset(keyset_filename);
  if (!keyset_handle.ok()) return keyset_handle.status();

  // Get the primitive.
  StatusOr<std::unique_ptr<Mac>> mac_primitive =
      (*keyset_handle)->GetPrimitive<Mac>();
  if (!mac_primitive.ok()) return mac_primitive.status();

  // Read the input.
  StatusOr<std::string> data_file_content = ReadFile(data_filename);
  if (!data_file_content.ok()) return data_file_content.status();

  std::string output;
  if (mode == kCompute) {
    // Compute authentication tag.
    StatusOr<std::string> compute_result =
        (*mac_primitive)->ComputeMac(*data_file_content);
    if (!compute_result.ok()) return compute_result.status();
    // Write out the authentication tag to tag file.
    return WriteToFile(*compute_result, tag_filename);
  } else {  // operation == kVerify.
    // Read the authentication tag from tag file.
    StatusOr<std::string> tag_result = ReadFile(tag_filename);
    if (!tag_result.ok()) {
      std::cerr << tag_result.status().message() << std::endl;
      exit(1);
    }
    // Verify authentication tag.
    Status verify_result =
        (*mac_primitive)->VerifyMac(*tag_result, *data_file_content);
    if (verify_result.ok()) std::clog << "Verification succeeded!" << std::endl;
    return verify_result;
  }
}

}  // namespace tink_cc_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string keyset_filename = absl::GetFlag(FLAGS_keyset_filename);
  std::string data_filename = absl::GetFlag(FLAGS_data_filename);
  std::string tag_filename = absl::GetFlag(FLAGS_tag_filename);

  std::clog << "Using keyset from file '" << keyset_filename << "' to " << mode
            << " authentication tag from file '" << tag_filename
            << "' for data file '" << data_filename << "'." << std::endl;
  std::clog << "The tag will be "
            << ((mode == kCompute) ? "written to" : "read from") << " file '"
            << tag_filename << "'." << std::endl;

  CHECK_OK(tink_cc_examples::MacCli(mode, keyset_filename, data_filename,
                                    tag_filename));
  return 0;
}
// [END mac-example]
