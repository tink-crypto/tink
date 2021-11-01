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

#include "tink/util/file_output_stream.h"

#include <unistd.h>
#include <cstring>
#include <algorithm>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/output_stream.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

namespace {

// Attempts to close file descriptor fd, while ignoring EINTR.
// (code borrowed from ZeroCopy-streams)
int close_ignoring_eintr(int fd) {
  int result;
  do {
    result = close(fd);
  } while (result < 0 && errno == EINTR);
  return result;
}


// Attempts to write 'count' bytes of data data from 'buf'
// to file descriptor fd, while ignoring EINTR.
int write_ignoring_eintr(int fd, const void *buf, size_t count) {
  int result;
  do {
    result = write(fd, buf, count);
  } while (result < 0 && errno == EINTR);
  return result;
}

}  // anonymous namespace


FileOutputStream::FileOutputStream(int file_descriptor, int buffer_size) :
    buffer_size_(buffer_size > 0 ? buffer_size : 128 * 1024) {  // 128 KB
  fd_ = file_descriptor;
  count_in_buffer_ = 0;
  count_backedup_ = 0;
  buffer_ = nullptr;
  position_ = 0;
  buffer_offset_ = 0;
  status_ = OkStatus();
}

crypto::tink::util::StatusOr<int> FileOutputStream::Next(void** data) {
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
  int write_result = write_ignoring_eintr(fd_, buffer_.get(), buffer_size_);
  if (write_result <= 0) {  // No data written or an I/O error occurred.
    if (write_result == 0) {
      return 0;
    }
    status_ = ToStatusF(absl::StatusCode::kInternal, "I/O error upon write: %d",
                        errno);
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

void FileOutputStream::BackUp(int count) {
  if (!status_.ok() || count < 1 || count_in_buffer_ == 0) return;
  int curr_buffer_size = buffer_size_ - buffer_offset_;
  int actual_count = std::min(count, curr_buffer_size - count_backedup_);
  count_backedup_ += actual_count;
  count_in_buffer_ -= actual_count;
  position_ -= actual_count;
}

FileOutputStream::~FileOutputStream() {
  Close().IgnoreError();
}

Status FileOutputStream::Close() {
  if (!status_.ok()) return status_;
  if (count_in_buffer_ > 0) {
    // Try to write the remaining bytes.
    int total_written = 0;
    while (total_written < count_in_buffer_) {
      int write_result = write_ignoring_eintr(
          fd_, buffer_.get() + total_written, count_in_buffer_ - total_written);
      if (write_result < 0) {  // An I/O error occurred.
        status_ = ToStatusF(absl::StatusCode::kInternal,
                            "I/O error upon write: %d", errno);
        return status_;
      } else if (write_result == 0) {  // No progress, hence abort.
        status_ =
            ToStatusF(absl::StatusCode::kInternal,
                      "I/O error: failed to write %d bytes before closing.",
                      count_in_buffer_ - total_written);
        return status_;
      }
      // Managed to write some bytes, hence continue.
      total_written += write_result;
    }
  }
  if (close_ignoring_eintr(fd_) == -1) {
    status_ = ToStatusF(absl::StatusCode::kInternal, "I/O error upon close: %d",
                        errno);
    return status_;
  }
  status_ = Status(absl::StatusCode::kFailedPrecondition, "Stream closed");
  return OkStatus();
}

int64_t FileOutputStream::Position() const {
  return position_;
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
