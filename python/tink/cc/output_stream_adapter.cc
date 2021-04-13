// Copyright 2020 Google LLC
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

#include "tink/cc/output_stream_adapter.h"

#include <algorithm>

#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<int64_t> OutputStreamAdapter::Write(absl::string_view data) {
  void* buffer;
  int64_t written = 0;
  while (written < data.size()) {
    auto next_result = stream_->Next(&buffer);
    if (!next_result.ok()) return next_result.status();
    int available = next_result.ValueOrDie();
    int write_count =
        std::min(available, static_cast<int>(data.size() - written));
    memcpy(buffer, data.data() + written, write_count);
    if (write_count < available) stream_->BackUp(available - write_count);
    written += write_count;
  }
  return written;
}

util::Status OutputStreamAdapter::Close() { return stream_->Close(); }

}  // namespace tink
}  // namespace crypto
