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

#include "tink/util/istream_input_stream.h"

#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <istream>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/input_stream.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

IstreamInputStream::IstreamInputStream(std::unique_ptr<std::istream> input,
                                       int buffer_size) :
    buffer_size_(buffer_size > 0 ? buffer_size : 128 * 1024) {  // 128 KB
  input_ = std::move(input);
  count_in_buffer_ = 0;
  count_backedup_ = 0;
  position_ = 0;
  buffer_ = absl::make_unique<uint8_t[]>(buffer_size_);
  buffer_offset_ = 0;
  status_ = util::OkStatus();
}

crypto::tink::util::StatusOr<int> IstreamInputStream::Next(const void** data) {
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
  input_->read(reinterpret_cast<char*>(buffer_.get()), buffer_size_);
  int count_read = input_->gcount();
  if (count_read == 0) {  // Could not read bytes, EOF or an I/O error.
    if (input_->good()) return count_read;  // No bytes could be read.
    // If !good(), distinguish EOF from other failures.
    if (input_->eof()) {
      status_ = Status(absl::StatusCode::kOutOfRange, "EOF");
    } else {
      status_ = ToStatusF(absl::StatusCode::kInternal, "I/O error: %s",
                          strerror(errno));
    }
    return status_;
  }
  buffer_offset_ = 0;
  count_backedup_ = 0;
  count_in_buffer_ = count_read;
  position_ = position_ + count_in_buffer_;
  *data = buffer_.get();
  return count_in_buffer_;
}

void IstreamInputStream::BackUp(int count) {
  if (!status_.ok() || count < 1 || count_backedup_ == count_in_buffer_) return;
  int actual_count = std::min(count, count_in_buffer_ - count_backedup_);
  count_backedup_ = count_backedup_ + actual_count;
  position_ = position_ - actual_count;
}

IstreamInputStream::~IstreamInputStream() {
}

int64_t IstreamInputStream::Position() const {
  return position_;
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
