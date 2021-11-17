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

#include "tink/internal/test_file_util.h"

#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace crypto {
namespace tink {
namespace internal {

using ::bazel::tools::cpp::runfiles::Runfiles;

std::string RunfilesPath(absl::string_view path) {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(Runfiles::CreateForTest(&error));
  if (runfiles == nullptr) {
    std::clog << "Unable to determine runfile path: " << error;
    exit(1);
  }

  const char* workspace_dir = getenv("TEST_WORKSPACE");
  if (workspace_dir == nullptr || workspace_dir[0] == '\0') {
    std::clog << "Unable to determine workspace name." << std::endl;
    exit(1);
  }

  return runfiles->Rlocation(absl::StrCat(workspace_dir, "/", path));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
