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

#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/mac_factory.h"
#include "tink/util/status.h"
#include "tools/testing/cc/cli_util.h"

using crypto::tink::MacFactory;
using crypto::tink::KeysetHandle;

// A command-line utility for testing Mac-primitives.
// It requires 4 for MAC computation and 5 for MAC verification:
//   keyset-file:  name of the file with the keyset to be used for MAC
//   operation: the actual MAC-operation, i.e. "compute" or "verify"
//   data-file:  name of the file with data for MAC computation/verification
//   mac-file:  name of the file for MAC value (when computing the MAC),
//              or with MAC value (when verifying the MAC)
//   result-file: name of the file for MAC verification result (valid/invalid)
//                (only for MAC verification operation)
int main(int argc, char** argv) {
  if (argc != 5 && argc != 6) {
    std::clog << "Usage: " << argv[0]
         << " keyset-file operation data-file mac-file [result-file]\n";
    exit(1);
  }
  std::string keyset_filename(argv[1]);
  std::string operation(argv[2]);
  std::string data_filename(argv[3]);
  std::string mac_filename(argv[4]);
  std::string result_filename = "";
  if (!(operation == "compute" || operation == "verify")) {
    std::clog << "Unknown operation '" << operation << "'.\n"
              << "Expected 'compute' or 'verify'.\n";
    exit(1);
  }
  if (operation == "compute") {
    std::clog << "Using keyset from file " << keyset_filename
              << " to compute MAC of data from file "<< data_filename
              << std::endl
              << "The resulting MAC will be written to file "
              << mac_filename << std::endl;
  } else {  // operation == "verify"
    result_filename = std::string(argv[5]);
    std::clog << "Using keyset from file " << keyset_filename
              << " to verify MAC value from file "<< mac_filename
              << " computed for data from file " << data_filename
              << std::endl
              << "The verification result will be written to file "
              << result_filename << std::endl;
  }

  // Init Tink;
  CliUtil::InitTink();

  // Read the keyset.
  std::unique_ptr<KeysetHandle> keyset_handle =
      CliUtil::ReadKeyset(keyset_filename);

  // Get the primitive.
  auto primitive_result = MacFactory::GetPrimitive(*keyset_handle);
  if (!primitive_result.ok()) {
    std::clog << "Getting MAC-primitive from the factory failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<crypto::tink::Mac> mac =
      std::move(primitive_result.ValueOrDie());

  // Read the data.
  std::string data = CliUtil::Read(data_filename);

  // Compute and write the output.
  if (operation == "compute") {
    std::clog << "computing MAC...\n";
    auto mac_result = mac->ComputeMac(data);
    if (!mac_result.ok()) {
      std::clog << "Error while computing the MAC:"
                << mac_result.status().error_message() << std::endl;
      exit(1);
    }
    CliUtil::Write(mac_result.ValueOrDie(), mac_filename);
  } else {  // operation == "verify"
    std::clog << "verifying MAC...\n";
    std::string mac_value = CliUtil::Read(mac_filename);
    std::string result = "valid";
    auto status = mac->VerifyMac(mac_value, data);
    if (!status.ok()) {
      std::clog << "Error while verifying MAC:"
                << status.error_message() << std::endl;
      result = "invalid";
    }
    CliUtil::Write(result, result_filename);
  }

  std::clog << "All done.\n";
  return 0;
}
