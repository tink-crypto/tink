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

#ifndef TINK_UTIL_OSTREAM_OUTPUT_STREAM_H_
#define TINK_UTIL_OSTREAM_OUTPUT_STREAM_H_

#include <memory>
#include <ostream>

#include "tink/output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

// An OutputStream that writes to an ostream.
class OstreamOutputStream : public crypto::tink::OutputStream {
 public:
  // Constructs an OutputStream that will write to the ostream specified
  // via 'output', using a buffer of the specified size, if any
  // (if no legal 'buffer_size' is given, a reasonable default will be used).
  explicit OstreamOutputStream(std::unique_ptr<std::ostream> output,
                               int buffer_size = -1);

  ~OstreamOutputStream() override;

  crypto::tink::util::StatusOr<int> Next(void** data) override;

  void BackUp(int count) override;

  crypto::tink::util::Status Close() override;

  int64_t Position() const override;

 private:
  util::Status status_;
  std::unique_ptr<std::ostream> output_;
  std::unique_ptr<uint8_t[]> buffer_;
  const int buffer_size_;
  int64_t position_;     // current position in the ostream (from the beginning)

  // Counters that describe the state of the data in buffer_.
  // count_in_buffer_ is always equal to (buffer_size_ - count_backedup_),
  // except initially (before the first call to Next()).
  // In other words, we have an invariant:
  // (count_in_buffer_ == buffer_size_ - count_backedup_) || buffer_ == nullptr
  int count_in_buffer_;  // # bytes in buffer_ that will be eventually written
  int count_backedup_;   // # bytes in buffer_ that were backed up
  int buffer_offset_;    // offset where the returned *data starts in buffer_
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_OSTREAM_OUTPUT_STREAM_H_
