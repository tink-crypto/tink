// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/buffered_input_stream.h"

#include <algorithm>
#include <cstring>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/input_stream.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace streamingaead {

using util::Status;
using util::StatusOr;

BufferedInputStream::BufferedInputStream(
    std::unique_ptr<crypto::tink::InputStream> input_stream) {
  input_stream_ = std::move(input_stream);
  count_in_buffer_ = 0;
  count_backedup_ = 0;
  position_ = 0;
  buffer_.resize(4 * 1024);  // 4 KB
  buffer_offset_ = 0;
  after_rewind_ = false;
  rewinding_enabled_ = true;
  direct_access_ = false;
  status_ = util::OkStatus();
}

crypto::tink::util::StatusOr<int> BufferedInputStream::Next(const void** data) {
  if (direct_access_) return input_stream_->Next(data);
  if (!status_.ok()) return status_;

  // We're just after rewind, so return all the data in the buffer, if any.
  if (after_rewind_ && count_in_buffer_ > 0) {
    after_rewind_ = false;
    *data = buffer_.data();
    position_ = count_in_buffer_;
    return count_in_buffer_;
  }
  if (count_backedup_ > 0) {  // Return the backed-up bytes.
    buffer_offset_ = count_in_buffer_ - count_backedup_;
    *data = buffer_.data() + buffer_offset_;
    int backedup = count_backedup_;
    count_backedup_ = 0;
    position_ = count_in_buffer_;
    return backedup;
  }

  // Read new bytes from input_stream_.
  //
  // If we don't allow rewind any more, all the data buffered so far
  // can be discarded, and from now on we go directly to input_stream_
  if (!rewinding_enabled_) {
    direct_access_ = true;
    buffer_.resize(0);
    return input_stream_->Next(data);
  }

  // Otherwise, we read from input_stream_ the next chunk of data,
  // and append it to buffer_.
  after_rewind_ = false;
  const void* buf;
  auto next_result = input_stream_->Next(&buf);
  if (!next_result.ok()) {
    status_ = next_result.status();
    return status_;
  }
  size_t count_read = next_result.ValueOrDie();
  if (buffer_.size() < count_in_buffer_ + count_read) {
    buffer_.resize(buffer_.size() + std::max(buffer_.size(), count_read));
  }
  memcpy(buffer_.data() + count_in_buffer_, buf, count_read);
  buffer_offset_ = count_in_buffer_;
  count_backedup_ = 0;
  count_in_buffer_ += count_read;
  position_ = position_ + count_read;
  *data = buffer_.data() + buffer_offset_;
  return count_read;
}

void BufferedInputStream::BackUp(int count) {
  if (direct_access_) {
    input_stream_->BackUp(count);
    return;
  }
  if (!status_.ok() || count < 1 ||
      count_backedup_ == (count_in_buffer_ - buffer_offset_)) {
    return;
  }
  int actual_count = std::min(
      count, count_in_buffer_ - buffer_offset_ - count_backedup_);
  count_backedup_ += actual_count;
  position_ = position_ - actual_count;
}

void BufferedInputStream::DisableRewinding() {
  rewinding_enabled_ = false;
}

crypto::tink::util::Status BufferedInputStream::Rewind() {
  if (!rewinding_enabled_) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "rewinding is disabled");
  }
  if (status_.ok() || status_.code() == absl::StatusCode::kOutOfRange) {
    status_ = util::OkStatus();
    position_ = 0;
    count_backedup_ = 0;
    buffer_offset_ = 0;
    after_rewind_ = true;
  }
  return status_;
}


BufferedInputStream::~BufferedInputStream() {
}

int64_t BufferedInputStream::Position() const {
  if (direct_access_) return input_stream_->Position();
  return position_;
}

}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto
