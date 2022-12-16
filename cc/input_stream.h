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

#ifndef TINK_INPUT_STREAM_H_
#define TINK_INPUT_STREAM_H_

#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Abstract interface similar to an input stream, and to
// Protocol Buffers' google::protobuf::io::ZeroCopyInputStream.
class InputStream {
 public:
  InputStream() = default;
  virtual ~InputStream() = default;

  // Obtains a chunk of data from the stream.
  //
  // Preconditions:
  // * "data" is not NULL.
  //
  // Postconditions:
  // * If the returned status is not OK, there is no more data to return
  //   (status equal to OUT_OF_RANGE) or an error occurred
  //   (status not in {OK, OUT_OF_RANGE}.  All errors are permanent.
  // * Otherwise, the returned value is the number of bytes read and "data"
  //   points to a buffer containing these bytes.
  // * Ownership of this buffer remains with the stream, and the buffer
  //   remains valid only until some other non-const method of the stream
  //   is called or the stream is destroyed.
  // * It is legal for the returned buffer to have zero size, as long as
  //   repeatedly calling Next() eventually yields a buffer with non-zero
  //   size or a non-OK status.
  virtual crypto::tink::util::StatusOr<int> Next(const void** data) = 0;

  // Backs up a number of bytes, so that the next call to Next() returns
  // data again that was already returned by the last call to Next().
  // This is useful when writing procedures that are only supposed to read
  // up to a certain point in the input, then return.  If Next() returns a
  // buffer that goes beyond what you wanted to read, you can use BackUp()
  // to return to the point where you intended to finish.
  //
  // Preconditions:
  // * The last call to Next() must have returned status OK.
  //   If there was no Next()-call yet, or the last one failed,
  //   BackUp()-call is ignored.
  // * count must be less than or equal to the size of the last buffer
  //   returned by Next().  Non-positive count is ignored (no action on this
  //   stream), and count larger than the size of the last buffer is treated
  //   as equal to the size of the last buffer.
  //
  // Postconditions:
  // * The last "count" bytes of the last buffer returned by Next() will be
  //   pushed back into the stream.  Subsequent calls to Next() will return
  //   the same data again before producing new data.
  // * Repeated calls to BackUp() accumulate:
  //      BackUp(a);
  //      Backup(b);
  //   is equivalent to
  //      Backup(c);
  //   with c = max(0, a) + max(0, b).
  // * The actual result of BackUp()-call can be verified via Position().
  virtual void BackUp(int count) = 0;

  // Returns the current byte position in the stream.
  //
  // Preconditions:
  // * The last call to Next() ended with status in {OK, OUT_OF_RANGE}.
  //
  // Postconditions:
  // * Position equal to i means that the next call to Next() will
  //   return a data buffer starting at (i+1)st byte of the stream (if any).
  // * If the last call to Next() reached end of stream (status OUT_OF_RANGE),
  //   then returned value is the total number of bytes in the stream.
  // * If the last call to Next() ended with a failure, -1 is returned;
  virtual int64_t Position() const = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_INPUT_STREAM_H_
