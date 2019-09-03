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

#ifndef TINK_PYTHON_CC_SIMPLE_OUTPUT_STREAM_ADAPTER_H_
#define TINK_PYTHON_CC_SIMPLE_OUTPUT_STREAM_ADAPTER_H_

#include <memory>

#include "tink/output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/python/cc/simple_output_stream.h"

namespace crypto {
namespace tink {

// An OutputStream that writes to a SimpleOutputStream.
class SimpleOutputStreamAdapter : public crypto::tink::OutputStream {
 public:
  // Constructs an OutputStream that will write to the SimpleOutputStream
  // specified via 'stream', using a buffer of the specified size, if any
  // (if 'buffer_size' <= 0, a reasonable default will be used).
  explicit SimpleOutputStreamAdapter(std::unique_ptr<SimpleOutputStream> stream,
                                     int buffer_size = 0);

  ~SimpleOutputStreamAdapter() override;

  crypto::tink::util::StatusOr<int> Next(void** data) override;

  void BackUp(int count) override;

  crypto::tink::util::Status Close() override;

  int64_t Position() const override;

 private:
  util::Status status_;
  std::unique_ptr<SimpleOutputStream> stream_;
  std::string buffer_;
  bool is_first_call_;
  int64_t position_;  // current position in the underlying stream (from the
                      // beginning)

  // Counters that describe the state of the data in buffer_.
  int count_in_buffer_;  // # bytes in buffer_ that will be eventually written
  int buffer_offset_;    // offset where the returned *data starts in buffer_
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PYTHON_CC_SIMPLE_OUTPUT_STREAM_ADAPTER_H_
