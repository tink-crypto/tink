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

#include "tink/subtle/test_util.h"

#include <algorithm>
#include <string>

#include "absl/status/status.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace test {

const int DummyStreamSegmentEncrypter::kSegmentTagSize;
const char DummyStreamSegmentEncrypter::kLastSegment;
const char DummyStreamSegmentEncrypter::kNotLastSegment;

util::Status WriteToStream(OutputStream* output_stream,
                           absl::string_view contents, bool close_stream) {
  void* buffer;
  int pos = 0;
  int remaining = contents.length();
  int available_space = 0;
  int available_bytes = 0;
  while (remaining > 0) {
    auto next_result = output_stream->Next(&buffer);
    if (!next_result.ok()) return next_result.status();
    available_space = next_result.value();
    available_bytes = std::min(available_space, remaining);
    memcpy(buffer, contents.data() + pos, available_bytes);
    remaining -= available_bytes;
    pos += available_bytes;
  }
  if (available_space > available_bytes) {
    output_stream->BackUp(available_space - available_bytes);
  }
  return close_stream ? output_stream->Close() : util::OkStatus();
}

util::Status ReadFromStream(InputStream* input_stream, std::string* output) {
  if (input_stream == nullptr || output == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Illegal read from a stream");
  }
  const void* buffer;
  output->clear();
  while (true) {
    auto next_result = input_stream->Next(&buffer);
    if (next_result.status().code() == absl::StatusCode::kOutOfRange) {
      // End of stream.
      return util::OkStatus();
    }
    if (!next_result.ok()) return next_result.status();
    auto read_bytes = next_result.value();
    if (read_bytes > 0) {
      output->append(
          std::string(reinterpret_cast<const char*>(buffer), read_bytes));
    }
  }
  return util::OkStatus();
}

}  // namespace test
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
