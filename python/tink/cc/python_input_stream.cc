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

#include "tink/cc/python_input_stream.h"

#include <algorithm>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/match.h"
#include "tink/input_stream.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/cc/python_file_object_adapter.h"

namespace crypto {
namespace tink {

namespace {

bool is_eof(const util::Status& status) {
  return status.error_code() == util::error::UNKNOWN &&
         absl::StrContains(status.error_message(), "EOFError");
}

}  // namespace

PythonInputStream::PythonInputStream(
    std::shared_ptr<PythonFileObjectAdapter> adapter, int buffer_size) {
  if (buffer_size <= 0) buffer_size = 128 * 1024;  // 128 KB
  adapter_ = adapter;
  count_in_buffer_ = 0;
  count_backedup_ = 0;
  position_ = 0;
  subtle::ResizeStringUninitialized(&buffer_, buffer_size);
  buffer_offset_ = 0;
  status_ = util::OkStatus();
}

util::StatusOr<int> PythonInputStream::Next(const void** data) {
  if (!status_.ok()) return status_;

  if (count_backedup_ > 0) {  // Return the backed-up bytes.
    buffer_offset_ += count_in_buffer_ - count_backedup_;
    count_in_buffer_ = count_backedup_;
    count_backedup_ = 0;
    position_ += count_in_buffer_;
    *data = &buffer_[buffer_offset_];
    return count_in_buffer_;
  }

  // Read new bytes to buffer_.
  auto read_result = adapter_->Read(buffer_.size());
  if (is_eof(read_result.status())) {
    return status_ = util::Status(util::error::OUT_OF_RANGE, "EOF");
  } else if (read_result.status().code() == absl::StatusCode::kOutOfRange) {
    // We need to change the error code because for InputStream OUT_OF_RANGE
    // status always means EOF.
    return status_ = util::Status(util::error::UNKNOWN,
                                  read_result.status().error_message());
  } else if (!read_result.ok()) {
    return status_ = read_result.status();
  }
  std::string read_string = read_result.ValueOrDie();
  int count_read = read_string.length();
  buffer_.replace(0, count_read, read_string);
  buffer_offset_ = 0;
  count_backedup_ = 0;
  count_in_buffer_ = count_read;
  position_ += count_in_buffer_;
  *data = &buffer_[0];
  return count_in_buffer_;
}

void PythonInputStream::BackUp(int count) {
  if (!status_.ok() || count < 1 || count_backedup_ == count_in_buffer_) return;
  int actual_count = std::min(count, count_in_buffer_ - count_backedup_);
  count_backedup_ += actual_count;
  position_ -= actual_count;
}

PythonInputStream::~PythonInputStream() {}

int64_t PythonInputStream::Position() const { return position_; }

}  // namespace tink
}  // namespace crypto
