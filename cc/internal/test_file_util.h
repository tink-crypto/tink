// Copyright 2021 Google LLC
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

#ifndef TINK_INTERNAL_TEST_FILE_UTIL_H_
#define TINK_INTERNAL_TEST_FILE_UTIL_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

// File utilities for testing.
///////////////////////////////////////////////////////////////////////////////

// TODO(ckl): Move other file related functionality from cc/util/test_util.h

// Returns the path of the specified file in the runfiles directory.
std::string RunfilesPath(absl::string_view path);

crypto::tink::util::Status CreateTestFile(absl::string_view filename,
                                          absl::string_view file_content);

// Returns the prefix to use for files to use in tests. The result will be of
// the form: <test name>_<testcase name>_<hex encoded random 32 bytes string>.
std::string GetTestFileNamePrefix();

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TEST_FILE_UTIL_H_
