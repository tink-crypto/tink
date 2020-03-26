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

#include "tink/cc/input_stream_adapter.h"

#include <algorithm>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

namespace {

util::StatusOr<absl::string_view> Read1NoCopy(InputStream* stream,
                                              int64_t size) {
  const void* buffer;
  auto next_result = stream->Next(&buffer);
  if (!next_result.ok()) return next_result.status();
  int available = next_result.ValueOrDie();
  int read_count =
      size < 0 ? available : std::min(static_cast<int64_t>(available), size);
  if (read_count < available) stream->BackUp(available - read_count);
  return absl::string_view(static_cast<const char*>(buffer), read_count);
}

}  // namespace

util::StatusOr<std::string> InputStreamAdapter::Read1(int64_t size) {
  auto result = Read1NoCopy(stream_.get(), size);
  if (!result.ok()) return result.status();
  return std::string(result.ValueOrDie());
}

util::StatusOr<std::string> InputStreamAdapter::Read(int64_t size) {
  std::string buffer;
  while (buffer.size() < size || size < 0) {
    auto result =
        Read1NoCopy(stream_.get(), size < 0 ? -1 : size - buffer.size());
    if (!result.ok()) {
      if (buffer.empty()) {
        return result.status();
      } else {
        break;
      }
    }
    auto data = result.ValueOrDie();
    if (data.empty()) break;
    absl::StrAppend(&buffer, data);
  }
  return buffer;
}

}  // namespace tink
}  // namespace crypto
