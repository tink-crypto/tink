// Copyright 2019 Google LLC
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

#ifndef TINK_STREAMINGAEAD_SHARED_INPUT_STREAM_H_
#define TINK_STREAMINGAEAD_SHARED_INPUT_STREAM_H_

#include "tink/input_stream.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace streamingaead {

// An InputStream that wraps another InputStream as a non-owned pointer.
// The wrapper forwards all calls to the wrapped InputStream,
// which must remain alive as long as as the wrapper is in use.
class SharedInputStream : public crypto::tink::InputStream {
 public:
  // Constructs an InputStream that wraps 'input_stream',
  // and will forward all the method calls to this wrapped stream.
  explicit SharedInputStream(
      crypto::tink::InputStream* input_stream)
      : input_stream_(input_stream) {}

  ~SharedInputStream() override {}

  crypto::tink::util::StatusOr<int> Next(const void** data) override {
    return input_stream_->Next(data);
  }

  void BackUp(int count) override {
    input_stream_->BackUp(count);
  }

  int64_t Position() const override {
    return input_stream_->Position();
  }

 private:
  crypto::tink::InputStream* input_stream_;
};

}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_SHARED_INPUT_STREAM_H_
