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

#include "tink/util/input_stream_util.h"

#include "absl/strings/str_cat.h"

namespace crypto {
namespace tink {

crypto::tink::util::StatusOr<std::string> ReadAtMostFromStream(
    int num_bytes, InputStream* input_stream) {
  const void* buffer;
  std::string result;
  int num_bytes_read = 0;

  while (num_bytes_read < num_bytes) {
    auto next_result = input_stream->Next(&buffer);
    if (!next_result.ok()) {
      if (next_result.status().error_code() == util::error::OUT_OF_RANGE) {
        return result;
      }
      return next_result.status();
    }

    int num_bytes_to_copy =
        std::min(num_bytes - num_bytes_read, next_result.ValueOrDie());
    input_stream->BackUp(next_result.ValueOrDie() - num_bytes_to_copy);
    absl::StrAppend(&result, std::string(reinterpret_cast<const char*>(buffer),
                                         num_bytes_to_copy));
    num_bytes_read += num_bytes_to_copy;
  }
  return result;
}

}  // namespace tink
}  // namespace crypto
