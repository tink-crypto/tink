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

#ifndef TINK_STREAMINGAEAD_SHARED_RANDOM_ACCESS_STREAM_H_
#define TINK_STREAMINGAEAD_SHARED_RANDOM_ACCESS_STREAM_H_

#include "tink/random_access_stream.h"
#include "tink/util/buffer.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace streamingaead {

// A RandomAccessStream that wraps another RandomAccessStream
// as a non-owned pointer.
// The wrapper forwards all calls to the wrapped RandomAccessStream,
// which must remain alive as long as as the wrapper is in use.
class SharedRandomAccessStream : public crypto::tink::RandomAccessStream {
 public:
  // Constructs an RandomAccessStream that wraps 'random_access_stream',
  // and will forward all the method calls to this wrapped stream.
  explicit SharedRandomAccessStream(
      crypto::tink::RandomAccessStream* random_access_stream)
      : random_access_stream_(random_access_stream) {}

  ~SharedRandomAccessStream() override {}

  crypto::tink::util::Status PRead(
      int64_t position, int count,
      crypto::tink::util::Buffer* dest_buffer) override {
    return random_access_stream_->PRead(position, count, dest_buffer);
  }

  crypto::tink::util::StatusOr<int64_t> size() override {
    return random_access_stream_->size();
  }

 private:
  crypto::tink::RandomAccessStream* random_access_stream_;
};

}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_SHARED_RANDOM_ACCESS_STREAM_H_
