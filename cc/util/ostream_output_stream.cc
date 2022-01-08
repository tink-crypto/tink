// Copyright 2018 Google Inc.
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

#include "tink/util/ostream_output_stream.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <memory>
#include <ostream>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/output_stream.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

OstreamOutputStream::OstreamOutputStream(std::unique_ptr<std::ostream> output,
                                         int buffer_size) :
    buffer_size_(buffer_size > 0 ? buffer_size : 128 * 1024) {  // 128 KB
  output_ = std::move(output);
  count_in_buffer_ = 0;
  count_backedup_ = 0;
  buffer_ = nullptr;
  position_ = 0;
  buffer_offset_ = 0;
  status_ = OkStatus();
}

crypto::tink::util::StatusOr<int> OstreamOutputStream::Next(void** data) {
  if (!status_.ok()) return status_;

  if (buffer_ == nullptr) {  // possible only at the first call to Next()
    buffer_ = absl::make_unique<uint8_t[]>(buffer_size_);
    *data = buffer_.get();
    count_in_buffer_ = buffer_size_;
    position_ = buffer_size_;
    return buffer_size_;
  }

  // If some space was backed up, return it first.
  if (count_backedup_ > 0) {
    position_ = position_ + count_backedup_;
    buffer_offset_ = count_in_buffer_;
    count_in_buffer_ = count_in_buffer_ + count_backedup_;
    int backedup = count_backedup_;
    count_backedup_ = 0;
    *data = buffer_.get() + buffer_offset_;
    return backedup;
  }

  // No space was backed up, so count_in_buffer_ == buffer_size_ holds here.
  // Write the data from the buffer, and return available space in buffer_.
  // The available space might not span the entire buffer_, as writing
  // may succeed only for a prefix of buffer_ -- in this case the data still
  // to be written is shifted in buffer_ and the remaining space is returned.
  int write_result = output_->rdbuf()->sputn(
      reinterpret_cast<char*>(buffer_.get()), buffer_size_);
  if (write_result == 0) {  // No data written or an I/O error occurred.
    if (output_->good()) return 0;
    status_ = ToStatusF(absl::StatusCode::kInternal, "I/O error upon write: %s",
                        std::strerror(errno));
    return status_;
  }
  // Some data was written, so we can return some portion of buffer_.
  position_ = position_ + write_result;
  count_in_buffer_ = buffer_size_;
  count_backedup_ = 0;
  buffer_offset_ = buffer_size_ - write_result;
  *data = buffer_.get() + buffer_offset_;
  if (write_result < buffer_size_) {
    // Only part of the data was written, shift the remaining data in buffer_.
    // Using memmove, as source and destination may overlap.
    std::memmove(buffer_.get(), buffer_.get() + write_result, buffer_offset_);
  }
  return write_result;
}

void OstreamOutputStream::BackUp(int count) {
  if (!status_.ok() || count < 1 || count_in_buffer_ == 0) return;
  int curr_buffer_size = buffer_size_ - buffer_offset_;
  int actual_count = std::min(count, curr_buffer_size - count_backedup_);
  count_backedup_ += actual_count;
  count_in_buffer_ -= actual_count;
  position_ -= actual_count;
}

OstreamOutputStream::~OstreamOutputStream() {
  Close().IgnoreError();
}

Status OstreamOutputStream::Close() {
  if (!status_.ok()) return status_;
  if (count_in_buffer_ > 0) {
    // Try to write the remaining bytes.
    output_->write(reinterpret_cast<char*>(buffer_.get()), count_in_buffer_);
    if (!output_->good()) {  // An I/O error occurred.
      status_ = ToStatusF(absl::StatusCode::kInternal,
                          "I/O error upon write: %d", errno);
      return status_;
    }
  }
  output_->flush();
  if (!output_->good()) {
    status_ = ToStatusF(absl::StatusCode::kInternal,
                        "I/O error upon flushing: %d", errno);
    return status_;
  }
  status_ = Status(absl::StatusCode::kFailedPrecondition, "Stream closed");
  return OkStatus();
}

int64_t OstreamOutputStream::Position() const {
  return position_;
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
