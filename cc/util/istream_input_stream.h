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

#ifndef TINK_UTIL_ISTREAM_INPUT_STREAM_H_
#define TINK_UTIL_ISTREAM_INPUT_STREAM_H_

#include <istream>
#include <memory>

#include "tink/input_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

// An InputStream that reads from a std::istream.
class IstreamInputStream : public crypto::tink::InputStream {
 public:
  // Constructs an InputStream that will read from the 'input' istream,
  // using a buffer of the specified size, if any (if no legal 'buffer_size'
  // is given, a reasonable default will be used).
  explicit IstreamInputStream(std::unique_ptr<std::istream> input,
                              int buffer_size = -1);

  ~IstreamInputStream() override;

  crypto::tink::util::StatusOr<int> Next(const void** data) override;

  void BackUp(int count) override;

  int64_t Position() const override;

 private:
  util::Status status_;
  std::unique_ptr<std::istream> input_;
  std::unique_ptr<uint8_t[]> buffer_;
  const int buffer_size_;
  int64_t position_;     // current position in the istream (from the beginning)

  // Counters that describe the state of the data in buffer_.
  int count_in_buffer_;  // # of bytes available in buffer_
  int count_backedup_;   // # of bytes available in buffer_ that were backed up
  int buffer_offset_;    // offset at which the returned bytes start in buffer_
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_ISTREAM_INPUT_STREAM_H_
