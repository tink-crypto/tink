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

#ifndef TINK_STREAMINGAEAD_BUFFERED_INPUT_STREAM_H_
#define TINK_STREAMINGAEAD_BUFFERED_INPUT_STREAM_H_

#include <memory>
#include <vector>

#include "tink/input_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace streamingaead {

// An InputStream that initially buffers all the read bytes, and offers
// rewind-functionality, until explicitly instructed to disable
// rewinding (and stop buffering).
class BufferedInputStream : public crypto::tink::InputStream {
 public:
  // Constructs an InputStream that will read from 'input_stream',
  // buffering all the read bytes in memory, and offering rewinding
  // to the beginning of the stream (as long as rewinding is enabled).
  explicit BufferedInputStream(
      std::unique_ptr<crypto::tink::InputStream> input_stream);

  ~BufferedInputStream() override;

  crypto::tink::util::StatusOr<int> Next(const void** data) override;

  void BackUp(int count) override;

  int64_t Position() const override;

  // Rewinds this stream to the beginning (if rewinding is still enabled).
  crypto::tink::util::Status Rewind();

  // Disables rewinding.
  void DisableRewinding();

 private:
  std::unique_ptr<crypto::tink::InputStream> input_stream_;
  bool direct_access_;      // true iff we don't buffer any data any more

  // The fields below are valid and in use iff direct_access_ is false.
  // Once direct_access_ becomes true, all the calls to this stream's methods
  // are directly relayed to methods of input_stream_.
  crypto::tink::util::Status status_;
  std::vector<uint8_t> buffer_;
  bool after_rewind_;       // true iff no Next has been called after rewind
  bool rewinding_enabled_;  // true iff this stream can be rewound
  int64_t position_;     // current position in the stream (from the beginning)

  // Counters that describe the state of the data in buffer_.
  int count_in_buffer_;  // # of bytes available in buffer_
  int count_backedup_;   // # of bytes available in buffer_ that were backed up
  int buffer_offset_;    // offset at which the returned bytes start in buffer_
};

}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_BUFFERED_INPUT_STREAM_H_
