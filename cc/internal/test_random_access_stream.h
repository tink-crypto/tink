// Copyright 2023 Google LLC
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
#ifndef TINK_INTERNAL_TEST_RANDOM_ACCESS_STREAM_H_
#define TINK_INTERNAL_TEST_RANDOM_ACCESS_STREAM_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/random_access_stream.h"
#include "tink/util/buffer.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// A simple test-only RandomAccessStream implementation that reads from a
// std::string.
class TestRandomAccessStream : public RandomAccessStream {
 public:
  explicit TestRandomAccessStream(std::string content)
      : content_(std::move(content)) {}
  // Move only.
  TestRandomAccessStream(TestRandomAccessStream&& other) = default;
  TestRandomAccessStream& operator=(TestRandomAccessStream&& other) = default;
  TestRandomAccessStream(const TestRandomAccessStream&) = delete;
  TestRandomAccessStream& operator=(const TestRandomAccessStream&) = delete;

  util::Status PRead(int64_t position, int count,
                     util::Buffer* dest_buffer) override;

  util::StatusOr<int64_t> size() override { return content_.size(); }

 private:
  std::string content_;
};

// Reads the entire `random_access_stream` using a buffer of size `chunk_size`
// until no more bytes can be read, and puts the read bytes into `contents`.
// Returns the status of the last call to random_access_stream->PRead().
util::Status ReadAllFromRandomAccessStream(
    RandomAccessStream* random_access_stream, std::string& contents,
    int chunk_size = 42);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TEST_RANDOM_ACCESS_STREAM_H_
