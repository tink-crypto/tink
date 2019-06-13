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

#include "tink/util/file_random_access_stream.h"

#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>

#include "absl/memory/memory.h"
#include "tink/random_access_stream.h"
#include "tink/util/buffer.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace util {

using crypto::tink::util::Status;

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

}  // anonymous namespace

FileRandomAccessStream::FileRandomAccessStream(int file_descriptor) {
  fd_ = file_descriptor;
}

Status FileRandomAccessStream::PRead(int64_t position, int count,
                                     Buffer* dest_buffer) {
  if (dest_buffer == nullptr) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "dest_buffer must be non-null");
  }
  if (count < 0) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "count cannot be negative");
  }
  if (count > dest_buffer->allocated_size()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "buffer too small");
  }
  if (position < 0) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "position cannot be negative");
  }
  dest_buffer->set_size(count);
  if (count == 0) {
    return Status::OK;
  }
  int read_count = pread(fd_, dest_buffer->get_mem_block(), count, position);
  if (read_count == 0) {
    dest_buffer->set_size(0);
    return Status(util::error::OUT_OF_RANGE, "EOF");
  }
  if (read_count < 0) {
    dest_buffer->set_size(0);
    return ToStatusF(util::error::UNKNOWN, "I/O error: %d", errno);
  }
  dest_buffer->set_size(read_count);
  return Status::OK;
}

FileRandomAccessStream::~FileRandomAccessStream() {
  close_ignoring_eintr(fd_);
}

int64_t FileRandomAccessStream::size() const {
  struct stat s;
  if (fstat(fd_, &s) == -1) {
    return -1;
  } else {
    return s.st_size;
  }
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
