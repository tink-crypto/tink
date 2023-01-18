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

#ifndef TINK_UTIL_FILE_INPUT_STREAM_H_
#define TINK_UTIL_FILE_INPUT_STREAM_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "tink/input_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

// An InputStream that reads from a file descriptor.
class FileInputStream : public crypto::tink::InputStream {
 public:
  // Constructs an InputStream that will read from the file specified
  // via `file_descriptor`, using a buffer of the specified size, if any
  // (if no legal `buffer_size` is given, a reasonable default will be used).
  // Takes the ownership of the file, and will close it upon destruction.
  explicit FileInputStream(int file_descriptor, int buffer_size = -1);

  ~FileInputStream() override;

  crypto::tink::util::StatusOr<int> Next(const void** data) override;

  void BackUp(int count) override;

  int64_t Position() const override;

 private:
  // Status of the stream.
  util::Status status_ = util::OkStatus();
  int fd_;
  std::vector<uint8_t> buffer_;

  // Current position in the stream (from the beginning).
  int64_t position_ = 0;
  // Counters that describe the state of the data in buffer_.
  // # of bytes available in buffer_.
  int count_in_buffer_ = 0;
  // # of bytes available in buffer_ that were backed up.
  int count_backedup_ = 0;
  // offset at which the returned bytes start in buffer_.
  int buffer_offset_ = 0;
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_FILE_INPUT_STREAM_H_
