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

#ifndef TINK_UTIL_BUFFER_H_
#define TINK_UTIL_BUFFER_H_

#include <memory>

#include "absl/memory/memory.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {

class Buffer {
 public:
  // Creates a new Buffer which allocates a new memory block
  // of size 'allocated_size' and uses it for the actual data.
  // The allocated memory block is owned by this Buffer.
  static util::StatusOr<std::unique_ptr<Buffer>> New(int allocated_size);

  // Creates a new Buffer which uses the given 'mem_block' as a buffer
  // for the actual data.
  // Does NOT take the ownership of 'mem_block' which must be non-null,
  // must allocate at least 'allocated_size' bytes, and must remain alive
  // as long as the returned Buffer is in use.
  static util::StatusOr<std::unique_ptr<Buffer>> NewNonOwning(
      char* mem_block, int allocated_size);

  // Returns the internal memory block of this Buffer,
  // that holds the actual data.
  // A reading caller may read up to size() bytes from the block.
  // A writing caller may write up to allocated_size() bytes to the block,
  // and should accordingly adjust size via set_size(int).
  virtual char* const get_mem_block() const = 0;

  // Returns the allocated size of this buffer.
  virtual int allocated_size() const = 0;

  // Returns the current size of this buffer.
  virtual int size() const = 0;

  // Sets the size of this buffer to 'new_size', which must
  // be in range 0..allocated_size().
  // Returns OK iff 0 <= new_size <= allocated_size();
  virtual util::Status set_size(int new_size) = 0;

  virtual ~Buffer() = default;
};

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_BUFFER_H_
