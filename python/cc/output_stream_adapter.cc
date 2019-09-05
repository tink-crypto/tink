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

#include "tink/python/cc/output_stream_adapter.h"

#include <algorithm>

#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<int> OutputStreamAdapter::Write(absl::string_view data) {
  void* buffer;
  auto next_result = stream_->Next(&buffer);
  if (!next_result.ok()) return next_result.status();
  int available = next_result.ValueOrDie();
  int write_count = std::min(available, static_cast<int>(data.length()));
  memcpy(buffer, data.data(), write_count);
  if (write_count < available) stream_->BackUp(available - write_count);
  return write_count;
}

util::Status OutputStreamAdapter::Close() { return stream_->Close(); }

int64_t OutputStreamAdapter::Position() const { return stream_->Position(); }

}  // namespace tink
}  // namespace crypto
