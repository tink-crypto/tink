// Copyright 2023 Google LLC
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

#include "tink/internal/test_file_util.h"

#include <fstream>
#include <ios>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status CreateTestFile(absl::string_view filename,
                            absl::string_view file_content) {
  std::string full_filename = absl::StrCat(test::TmpDir(), "/", filename);
  std::ofstream output_stream(full_filename, std::ios::binary);
  if (!output_stream) {
    return util::Status(absl::StatusCode::kInternal, "Cannot open file");
  }
  output_stream.write(file_content.data(), file_content.size());
  return util::OkStatus();
}

std::string GetTestFileNamePrefix() {
  const testing::TestInfo* const test_info =
      testing::UnitTest::GetInstance()->current_test_info();
  CHECK(test_info != nullptr);
  std::string random_string = subtle::Random::GetRandomBytes(/*length=*/16);
  std::string test_suite_name = test_info->test_suite_name();
  std::string test_name = test_info->name();
  // Parametrized tests return test_suite_name of the form <Prefix>/<Test Suite>
  // and name of the form <Test Name>/<Suffix>.
  // In this case, get only the prefix and test name. Keeping all of these may
  // result in a file name that is too long.
  if (test_info->value_param() != nullptr) {
    std::vector<std::string> test_suite_parts =
        absl::StrSplit(test_info->test_suite_name(), '/');
    CHECK_GE(test_suite_parts.size(), 1);
    test_suite_name = test_suite_parts[0];
    std::vector<std::string> test_name_parts =
        absl::StrSplit(test_info->name(), '/');
    CHECK_GE(test_name_parts.size(), 1);
    test_name = test_name_parts[0];
  }
  return absl::StrCat(test_suite_name, "_", test_name, "_",
                      absl::BytesToHexString(random_string));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
