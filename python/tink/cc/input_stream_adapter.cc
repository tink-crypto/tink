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

#include "tink/cc/input_stream_adapter.h"

#include <algorithm>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<std::string> InputStreamAdapter::Read(int64_t size) {
  const void* buffer;
  auto next_result = stream_->Next(&buffer);
  if (!next_result.ok()) return next_result.status();
  int available = next_result.ValueOrDie();
  int read_count =
      size < 0 ? available : std::min(static_cast<int64_t>(available), size);
  if (read_count < available) stream_->BackUp(available - read_count);
  return std::string(
      absl::string_view(static_cast<const char*>(buffer), read_count));
}

}  // namespace tink
}  // namespace crypto
