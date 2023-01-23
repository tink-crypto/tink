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
#include "tink/internal/test_random_access_stream.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

namespace crypto {
namespace tink {
namespace internal {

util::Status TestRandomAccessStream::PRead(int64_t position, int count,
                                           util::Buffer* dest_buffer) {
  if (dest_buffer == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "dest_buffer must be non-null");
  }
  if (count <= 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "count must be positive");
  }
  if (count > dest_buffer->allocated_size()) {
    return util::Status(absl::StatusCode::kInvalidArgument, "buffer too small");
  }
  if (position < 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "position cannot be negative");
  }
  if (position >= content_.size()) {
    dest_buffer->set_size(0).IgnoreError();
    return util::Status(absl::StatusCode::kOutOfRange, "EOF");
  }
  util::Status status = dest_buffer->set_size(count);
  if (!status.ok()) {
    return status;
  }
  int read_count =
      std::min(count, static_cast<int>(content_.size() - position));
  std::copy(content_.begin() + position,
            content_.begin() + position + read_count,
            dest_buffer->get_mem_block());
  status = dest_buffer->set_size(read_count);
  if (!status.ok()) {
    return status;
  }
  if (position + read_count == content_.size()) {
    // We reached EOF.
    return util::Status(absl::StatusCode::kOutOfRange, "EOF");
  }
  return util::OkStatus();
}

util::Status ReadAllFromRandomAccessStream(
    RandomAccessStream* random_access_stream, std::string& contents,
    int chunk_size) {
  if (chunk_size < 1) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "chunk_size must be greater than zero");
  }
  contents.clear();
  std::unique_ptr<util::Buffer> buffer =
      *std::move(util::Buffer::New(chunk_size));
  int64_t position = 0;
  auto status = util::OkStatus();
  while (status.ok()) {
    status = random_access_stream->PRead(position, chunk_size, buffer.get());
    contents.append(buffer->get_mem_block(), buffer->size());
    position = contents.size();
  }
  return status;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
