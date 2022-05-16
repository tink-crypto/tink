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

#ifndef TINK_PYTHON_CC_PYTHON_OUTPUT_STREAM_H_
#define TINK_PYTHON_CC_PYTHON_OUTPUT_STREAM_H_

#include <memory>
#include <string>

#include "tink/output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/cc/python_file_object_adapter.h"

namespace crypto {
namespace tink {

// An OutputStream that writes to a PythonFileObjectAdapter.
class PythonOutputStream : public OutputStream {
 public:
  // Constructs an OutputStream that will write to the PythonFileObjectAdapter
  // specified via 'adapter', using a buffer of the specified size, if any
  // (if 'buffer_size' <= 0, a reasonable default will be used).
  explicit PythonOutputStream(std::shared_ptr<PythonFileObjectAdapter> adapter,
                              int buffer_size = 0);

  ~PythonOutputStream() override;

  crypto::tink::util::StatusOr<int> Next(void** data) override;

  void BackUp(int count) override;

  crypto::tink::util::Status Close() override;

  int64_t Position() const override;

 private:
  util::Status status_;
  std::shared_ptr<PythonFileObjectAdapter> adapter_;
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

#endif  // TINK_PYTHON_CC_PYTHON_OUTPUT_STREAM_H_
