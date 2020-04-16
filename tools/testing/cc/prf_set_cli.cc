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

#include <fstream>
#include <iostream>
#include <sstream>

#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "tink/keyset_handle.h"
#include "tink/prf/prf_set.h"
#include "tink/util/status.h"
#include "testing/cc/cli_util.h"

using crypto::tink::KeysetHandle;
using crypto::tink::PrfSet;

// A command-line utility for testing PrfSet-primitives.
// It requires 4 arguments:
//   keyset-file:  name of the file with the keyset to be used for PrfSet
//   data-file:  name of the file with data for PrfSet input
//   result-file: name of the file for PrfSet output.
//   output-length: length of the prf output in bytes.
//   Format of the output set: <prf_id>:hexencode(<prf_output>)
//   where <prf_id> is the uint32 decimal representation of the ID of the PRF.
//   If the requested output is too long the result should be instead
//   <prd_id>:--.
int main(int argc, char** argv) {
  if (argc != 5) {
    std::clog << "Usage: " << argv[0]
              << " keyset-file data-file prf-file output-length" << std::endl;
    exit(1);
  }
  std::string keyset_filename(argv[1]);
  std::string data_filename(argv[2]);
  std::string prf_filename(argv[3]);
  size_t output_length;
  if (!absl::SimpleAtoi(argv[4], &output_length)) {
    std::clog << "Output length \"" << argv[4]
              << "\"could not be parsed as integer." << std::endl;
    exit(1);
  }
  std::clog << "Using keyset from file " << keyset_filename
            << " to compute PRF of data from file " << data_filename
            << std::endl
            << "The resulting PRF output will be " << output_length
            << " bytes long and written to the file " << prf_filename
            << std::endl;

  // Init Tink;
  CliUtil::InitTink();

  // Read the keyset.
  std::unique_ptr<KeysetHandle> keyset_handle =
      CliUtil::ReadKeyset(keyset_filename);

  // Get the primitive.
  auto primitive_result = keyset_handle->GetPrimitive<PrfSet>();
  if (!primitive_result.ok()) {
    std::clog << "Getting PRF set-primitive from the keyset failed: "
              << primitive_result.status().error_message() << std::endl;
    exit(1);
  }
  std::unique_ptr<PrfSet> prf_set = std::move(primitive_result.ValueOrDie());

  // Read the data.
  std::string data = CliUtil::Read(data_filename);

  // Compute and write the output.
  std::stringstream result_stream;
  for (const auto& prf_result : prf_set->GetPrfs()) {
    std::clog << "computing PRF for id " << prf_result.first << "..."
              << std::endl;
    result_stream << prf_result.first << ":";
    auto prf_value_result = prf_result.second->Compute(data, output_length);
    if (!prf_value_result.ok()) {
      result_stream << "--" << std::endl;
    } else {
      result_stream << absl::BytesToHexString(prf_value_result.ValueOrDie())
                    << std::endl;
    }
  }
  CliUtil::Write(result_stream.str(), prf_filename);
  std::clog << "All done." << std::endl;
  return 0;
}
