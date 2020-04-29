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

#ifndef TINK_UTIL_SECRET_DATA_INTERNAL_H_
#define TINK_UTIL_SECRET_DATA_INTERNAL_H_

#include <cstdlib>
#include <iostream>
#include <limits>
#include <new>
#include <type_traits>

#include "absl/base/attributes.h"

namespace crypto {
namespace tink {
namespace util {
namespace internal {

// Functions to track sensitive memory locations.
// Used to sanitize the memory whenever needed.
// Tracking is not currently implemented for open-source Tink.
void TrackSensitiveMemory(void* ptr, std::size_t size);
void UntrackAndSanitizeSensitiveMemory(void* ptr, std::size_t size);

template <typename T>
ABSL_ATTRIBUTE_NORETURN void Throw(const T& error) {
  throw error;
}

template <typename T>
struct SanitizingAllocator {
  typedef T value_type;

  SanitizingAllocator() = default;
  template <class U>
  explicit constexpr SanitizingAllocator(
      const SanitizingAllocator<U>&) noexcept {}

  ABSL_MUST_USE_RESULT T* allocate(std::size_t n) {
    if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
      Throw(std::bad_alloc());
    }

    size_t size = n * sizeof(T);
    T* ptr = static_cast<T*>(std::malloc(size));
    if (!ptr) {
      Throw(std::bad_alloc());
    }

    TrackSensitiveMemory(ptr, size);
    return ptr;
  }

  void deallocate(T* ptr, std::size_t n) noexcept {
    UntrackAndSanitizeSensitiveMemory(ptr, n * sizeof(T));
    std::free(ptr);
  }

  // Allocator requirements mandate definition of eq and neq operators
  bool operator==(const SanitizingAllocator&) { return true; }
  bool operator!=(const SanitizingAllocator&) { return false; }
};

template <typename T>
struct SanitizingDeleter {
  static_assert(std::is_trivially_destructible<T>::value,
                "only trivial types allowed for SecretUniquePtr");

  void operator()(T* ptr) {
    if (!ptr) {
      return;
    }
    ptr->~T();  // Invoke destructor. Must do this before sanitize.
    UntrackAndSanitizeSensitiveMemory(ptr, sizeof(T));
    std::free(ptr);
  }
};

}  // namespace internal
}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_SECRET_DATA_INTERNAL_H_
