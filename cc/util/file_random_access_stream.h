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

#ifndef TINK_UTIL_FILE_RANDOM_ACCESS_STREAM_H_
#define TINK_UTIL_FILE_RANDOM_ACCESS_STREAM_H_

#include <cstdint>
#include <memory>

#include "tink/random_access_stream.h"
#include "tink/util/buffer.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

// An RandomAccessStream that reads from a file descriptor.
//
// NOTE: This class in not available when building on Windows.
class FileRandomAccessStream : public crypto::tink::RandomAccessStream {
 public:
  // Constructs a FileRandomAccessStream that will read from the file specified
  // via 'file_descriptor'.
  // Takes the ownership of the file, and will close it upon destruction.
  explicit FileRandomAccessStream(int file_descriptor);

  ~FileRandomAccessStream() override;

  crypto::tink::util::Status PRead(int64_t position,
                                   int count,
                                   Buffer* dest_buffer) override;

  crypto::tink::util::StatusOr<int64_t> size() override;

 private:
  int fd_;
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_FILE_RANDOM_ACCESS_STREAM_H_
