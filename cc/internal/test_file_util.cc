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
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
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

}  // namespace internal
}  // namespace tink
}  // namespace crypto
