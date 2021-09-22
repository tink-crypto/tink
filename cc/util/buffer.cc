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

#include "tink/util/buffer.h"

#include "absl/memory/memory.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

class OwningBuffer : public Buffer {
 public:
  // Constructs a new Buffer which allocates a new memory block
  // of size 'allocated_size' and uses it for the actual data.
  // The allocated memory block is owned by this Buffer.
  // It is assumed that 'allocated_size' is positive.
  explicit OwningBuffer(int allocated_size)
      : allocated_size_(allocated_size), size_(allocated_size) {
    owned_mem_block_ = absl::make_unique<char[]>(allocated_size);
  }

  char* const get_mem_block() const override  {
    return owned_mem_block_.get();
  }

  int allocated_size() const override { return allocated_size_; }

  int size() const override { return size_; }

  util::Status set_size(int new_size) override {
    if (new_size < 0  || new_size > allocated_size_) {
      return Status(crypto::tink::util::error::INVALID_ARGUMENT,
                    "new_size must satisfy 0 <= new_size <= allocated_size()");
    }
    size_ = new_size;
    return OkStatus();
  }

  ~OwningBuffer() override {}

 private:
  std::unique_ptr<char[]> owned_mem_block_;
  const int allocated_size_;
  int size_;
};


class NonOwningBuffer : public Buffer {
 public:
  // Constructs a new Buffer which uses the given 'mem_block' as a buffer
  // for the actual data.
  // Does NOT take the ownership of 'mem_block' which must be non-null,
  // must allocate at least 'allocated_size' bytes, and must remain alive
  // as long as the returned Buffer is in use.
  // It is assumed that 'mem_block' is non-null, and that
  // 'allocated_size' is positive.
  NonOwningBuffer(char* mem_block, int allocated_size)
      : mem_block_(mem_block),
        allocated_size_(allocated_size), size_(allocated_size) {}

  char* const get_mem_block() const override { return mem_block_; };

  int allocated_size() const override { return allocated_size_; }

  int size() const override { return size_; }

  util::Status set_size(int new_size) override {
    if (new_size < 0  || new_size > allocated_size_) {
      return Status(crypto::tink::util::error::INVALID_ARGUMENT,
                    "new_size must satisfy 0 <= new_size <= allocated_size()");
    }
    size_ = new_size;
    return OkStatus();
  }

  ~NonOwningBuffer() override {}

 private:
  char* const mem_block_;
  const int allocated_size_;
  int size_;
};

}  // namespace

// static
StatusOr<std::unique_ptr<Buffer>> Buffer::New(int allocated_size) {
  if (allocated_size <= 0) {
    return Status(crypto::tink::util::error::INVALID_ARGUMENT,
                  "allocated_size must be positive");
  }
  return {absl::make_unique<OwningBuffer>(allocated_size)};
}

// static
StatusOr<std::unique_ptr<Buffer>> Buffer::NewNonOwning(
    char* mem_block, int allocated_size) {
  if (allocated_size <= 0) {
    return Status(crypto::tink::util::error::INVALID_ARGUMENT,
                  "allocated_size must be positive");
  }
  if (mem_block == nullptr) {
    return Status(crypto::tink::util::error::INVALID_ARGUMENT,
                  "mem_block must be non-null");
  }
  return {absl::make_unique<NonOwningBuffer>(mem_block, allocated_size)};
}


}  // namespace util
}  // namespace tink
}  // namespace crypto
