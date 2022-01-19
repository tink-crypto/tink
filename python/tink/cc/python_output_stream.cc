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

#include "tink/cc/python_output_stream.h"

#include <algorithm>
#include <memory>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/output_stream.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/cc/python_file_object_adapter.h"

namespace crypto {
namespace tink {

PythonOutputStream::PythonOutputStream(
    std::shared_ptr<PythonFileObjectAdapter> adapter, int buffer_size) {
  if (buffer_size <= 0) buffer_size = 128 * 1024;  // 128 KB
  adapter_ = adapter;
  subtle::ResizeStringUninitialized(&buffer_, buffer_size);
  is_first_call_ = true;
  position_ = 0;
  count_in_buffer_ = 0;
  buffer_offset_ = 0;
  status_ = util::OkStatus();
}

crypto::tink::util::StatusOr<int> PythonOutputStream::Next(void** data) {
  if (!status_.ok()) return status_;

  // This is the first call to Next(), so we return the whole buffer.
  if (is_first_call_) {
    is_first_call_ = false;
    count_in_buffer_ = buffer_.size();
    position_ = buffer_.size();
    *data = &buffer_[0];
    return buffer_.size();
  }

  // If some space was backed up, return it first.
  if (count_in_buffer_ < buffer_.size()) {
    int count_backedup = buffer_.size() - count_in_buffer_;
    position_ += count_backedup;
    buffer_offset_ = count_in_buffer_;
    count_in_buffer_ = buffer_.size();
    *data = &buffer_[buffer_offset_];
    return count_backedup;
  }

  // Write the data from the buffer and return available space in the buffer.
  // The available space might not span the entire buffer, as writing
  // may succeed only for a prefix of the buffer -- in this case the data still
  // to be written is shifted in the buffer and the remaining space is returned.
  auto write_result = adapter_->Write(buffer_);
  if (!write_result.ok()) return status_ = write_result.status();

  // Some data was written, so we can return some portion of buffer_.
  int written = write_result.ValueOrDie();
  position_ += written;
  count_in_buffer_ = buffer_.size();
  buffer_offset_ = buffer_.size() - written;
  if (written < buffer_.size()) {
    // Only part of the data was written, shift the remaining data in buffer_.
    // Using memmove, as source and destination may overlap.
    std::memmove(&buffer_[0], &buffer_[written], buffer_offset_);
  }
  *data = &buffer_[buffer_offset_];
  return written;
}

void PythonOutputStream::BackUp(int count) {
  if (!status_.ok() || count < 1 || count_in_buffer_ == 0) return;
  int actual_count = std::min(count, count_in_buffer_ - buffer_offset_);
  count_in_buffer_ -= actual_count;
  position_ -= actual_count;
}

PythonOutputStream::~PythonOutputStream() { Close().IgnoreError(); }

util::Status PythonOutputStream::Close() {
  if (!status_.ok()) return status_;
  if (count_in_buffer_ > 0) {
    // Try to write the remaining bytes.
    int written = 0;
    while (written < count_in_buffer_) {
      auto write_result = adapter_->Write(absl::string_view(buffer_).substr(
          written, count_in_buffer_ - written));
      if (!write_result.ok()) return write_result.status();
      written += write_result.ValueOrDie();
    }
  }
  status_ = adapter_->Close();
  if (!status_.ok()) return status_;
  status_ =
      util::Status(absl::StatusCode::kFailedPrecondition, "Stream closed");
  return util::OkStatus();
}

int64_t PythonOutputStream::Position() const { return position_; }

}  // namespace tink
}  // namespace crypto
