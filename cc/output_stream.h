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

#ifndef TINK_OUTPUT_STREAM_H_
#define TINK_OUTPUT_STREAM_H_

#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Abstract interface similar to an output stream, and to
// Protocol Buffers' google::protobuf::io::ZeroCopyOutputStream.
class OutputStream {
 public:
  OutputStream() = default;
  virtual ~OutputStream() = default;

  // Obtains a buffer into which data can be written.  Any data written
  // into this buffer will eventually (maybe instantly, maybe later on)
  // be written to the output.
  //
  // Preconditions:
  // * "data" is not NULL.
  //
  // Postconditions:
  // * If the returned status is not OK, then an error occurred.
  //   All errors are permanent.
  // * Otherwise, the returned value is the actual number of bytes
  //   in the buffer and "data" points to the buffer.
  // * Ownership of this buffer remains with the stream, and the buffer
  //   remains valid only until some other non-const method of the stream
  //   is called or the stream is destroyed.
  // * Any data which the caller stores in this buffer will eventually be
  //   written to the output (unless BackUp() is called).
  // * It is legal for the returned buffer to have zero size, as long
  //   as repeatedly calling Next() eventually yields a buffer with non-zero
  //   size.
  virtual crypto::tink::util::StatusOr<int> Next(void** data) = 0;

  // Backs up a number of bytes, so that the end of the last buffer returned
  // by Next() is not actually written.  This is needed when you finish
  // writing all the data you want to write, but the last buffer was bigger
  // than you needed.  You don't want to write a bunch of garbage after the
  // end of your data, so you use BackUp() to back up.
  //
  // Preconditions:
  // * The last call to Next() must have returned status OK.
  //   If there was no Next()-call yet, or the last one failed,
  //   BackUp()-call is ignored.
  // * count must be less than or equal to the size of the last buffer
  //   returned by Next().  Non-positive count is ignored (no action on this
  //   stream), and count larger than the size of the last buffer is treated
  //   as equal to the size of the last buffer.
  // * The caller must not have written anything to the last "count" bytes
  //   of that buffer.
  //
  // Postconditions:
  // * The last "count" bytes of the last buffer returned by Next() will be
  //   ignored.
  // * Repeated calls to BackUp() accumulate:
  //      BackUp(a);
  //      Backup(b);
  //   is equivalent to
  //      Backup(c);
  //   with c = max(0, a) + max(0, b).
  // * The actual result of BackUp()-call can be verified via Position().
  virtual void BackUp(int count) = 0;

  // Closes this output stream. It flushes all the data from the last buffer
  // returned by Next(), (except the ones backed up via BackUp(), if any)
  // Returns a non-OK status if some error occurred.
  //
  // Preconditions:
  // * The stream is not closed yet,
  // * The last call to Next() did not return an error.
  //
  // Postconditions:
  // * Writing to the stream is not possible any more, and all calls
  //   to non-const methods will fail.
  virtual crypto::tink::util::Status Close() = 0;

  // Returns the total number of bytes written since this object was created.
  // Preconditions:
  // * The most recent call to Next() (if any) was successful, or the stream
  //   was successfully closed.
  //
  // Postconditions:
  // * The returned position includes the bytes from the most recent
  //   successful call to Next(), excluding the ones that were backed up
  //   via BackUp() (if any).
  // * If the last call to Next() ended with a failure, -1 is returned;
  virtual int64_t Position() const = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_OUTPUT_STREAM_H_
