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

#include "tink/util/file_input_stream.h"

#include <unistd.h>
#include <algorithm>

#include "absl/memory/memory.h"
#include "tink/input_stream.h"
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


// Attempts to read 'count' bytes of data data from file descriptor fd
// to 'buf' while ignoring EINTR.
int read_ignoring_eintr(int fd, void *buf, size_t count) {
  int result;
  do {
    result = read(fd, buf, count);
  } while (result < 0 && errno == EINTR);
  return result;
}

}  // anonymous namespace

FileInputStream::FileInputStream(int file_descriptor, int buffer_size) :
    buffer_size_(buffer_size > 0 ? buffer_size : 128 * 1024) {  // 128 KB
  fd_ = file_descriptor;
  count_in_buffer_ = 0;
  count_backedup_ = 0;
  position_ = 0;
  buffer_ = absl::make_unique<uint8_t[]>(buffer_size_);
  buffer_offset_ = 0;
  status_ = util::OkStatus();
}

crypto::tink::util::StatusOr<int> FileInputStream::Next(const void** data) {
  if (!status_.ok()) return status_;
  if (count_backedup_ > 0) {  // Return the backed-up bytes.
    buffer_offset_ = buffer_offset_ + (count_in_buffer_ - count_backedup_);
    count_in_buffer_ = count_backedup_;
    count_backedup_ = 0;
    *data = buffer_.get() + buffer_offset_;
    position_ = position_ + count_in_buffer_;
    return count_in_buffer_;
  }
  // Read new bytes to buffer_.
  int read_result = read_ignoring_eintr(fd_, buffer_.get(), buffer_size_);
  if (read_result <= 0) {  // EOF or an I/O error.
    if (read_result == 0) {
      status_ = Status(util::error::OUT_OF_RANGE, "EOF");
    } else {
      status_ =
          ToStatusF(util::error::INTERNAL, "I/O error: %d", read_result);
    }
    return status_;
  }
  buffer_offset_ = 0;
  count_backedup_ = 0;
  count_in_buffer_ = read_result;
  position_ = position_ + count_in_buffer_;
  *data = buffer_.get();
  return count_in_buffer_;
}

void FileInputStream::BackUp(int count) {
  if (!status_.ok() || count < 1 || count_backedup_ == count_in_buffer_) return;
  int actual_count = std::min(count, count_in_buffer_ - count_backedup_);
  count_backedup_ = count_backedup_ + actual_count;
  position_ = position_ - actual_count;
}

FileInputStream::~FileInputStream() {
  close_ignoring_eintr(fd_);
}

int64_t FileInputStream::Position() const {
  return position_;
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
