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

#ifndef TINK_RANDOM_ACCESS_STREAM_H_
#define TINK_RANDOM_ACCESS_STREAM_H_

#include <cstdint>

#include "tink/util/buffer.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Abstract interface for streams that provide random access for reading,
// like regular files.
class RandomAccessStream {
 public:
  RandomAccessStream() = default;
  virtual ~RandomAccessStream() = default;

  // Reads up to 'count' bytes starting at 'position' and writes them
  // to 'dest_buffer'.  'position' must be within the size of the stream,
  // 'count' must be positive, 'dest_buffer' must be non-NULL and its
  // allocated size must be not smaller than 'count'.
  //
  // Return values:
  //  OK: if exactly 'count' bytes were read and written to 'dest_buffer',
  //      or if fewer than 'count' (potentially 0) bytes were read,
  //      but the lack of bytes is not permanent, and retrying may succeed;
  //      in this case 'dest_buffer' contains the read bytes, and the size
  //      of the buffer has been changed to the number of bytes read.
  //  OUT_OF_RANGE: if the end of stream has been reached;
  //      in this case 'dest_buffer' contains the bytes read till the end
  //      of the stream (if any).  This status is returned also when
  //      'position' is larger than the current size of the stream.
  //  INVALID_ARGUMENT: if some of the arguments are not valid.
  //  other: if some other error occurred.
  virtual crypto::tink::util::Status PRead(
      int64_t position,
      int count,
      crypto::tink::util::Buffer* dest_buffer) = 0;

  // Returns the size of this stream in bytes, if available.
  // If the size is not available, returns a non-Ok status.
  // The returned value is the "logical" size of a stream, i.e. of
  // a sequence of bytes), stating how many bytes are there in the sequence.
  // For a successful PRead-operation the starting position should be
  // in the range 0..size()-1 (otherwise PRead may return a non-Ok status).
  virtual crypto::tink::util::StatusOr<int64_t> size() = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_RANDOM_ACCESS_STREAM_H_
