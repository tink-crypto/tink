// Copyright 2020 Google LLC
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

#ifndef TINK_UTIL_SECRET_DATA_INTERNAL_H_
#define TINK_UTIL_SECRET_DATA_INTERNAL_H_

#include <cstddef>
#include <cstdlib>
#include <limits>
#include <new>

#include "absl/base/attributes.h"
#include "absl/base/config.h"
#include "openssl/crypto.h"

namespace crypto {
namespace tink {
namespace util {
namespace internal {

inline void SafeZeroMemory(void* ptr, std::size_t size) {
  OPENSSL_cleanse(ptr, size);
}

template <typename T>
struct SanitizingAllocatorImpl {
  // If aligned operator new is not supported this only supports under aligned
  // types.
#ifndef __cpp_aligned_new
  static_assert(alignof(T) <= alignof(std::max_align_t),
                "SanitizingAllocator<T> only supports fundamental alignment "
                "before C++17");
#endif

  static T* allocate(std::size_t n) {
    if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
#ifdef ABSL_HAVE_EXCEPTIONS
      throw std::bad_array_new_length();
#else
      std::abort();
#endif
    }
    std::size_t size = n * sizeof(T);
#ifdef __cpp_aligned_new
    return static_cast<T*>(::operator new(size, std::align_val_t(alignof(T))));
#else
    return static_cast<T*>(::operator new(size));
#endif
  }

  static void deallocate(void* ptr, std::size_t n) {
    SafeZeroMemory(ptr, n * sizeof(T));
#ifdef __cpp_aligned_new
    ::operator delete(ptr, std::align_val_t(alignof(T)));
#else
    ::operator delete(ptr);
#endif
  }
};

// Specialization for malloc-like aligned storage.
template <>
struct SanitizingAllocatorImpl<void> {
  static void* allocate(std::size_t n) { return std::malloc(n); }
  static void deallocate(void* ptr, std::size_t n) {
    SafeZeroMemory(ptr, n);
    return std::free(ptr);
  }
};

template <typename T>
struct SanitizingAllocator {
  typedef T value_type;

  SanitizingAllocator() = default;
  template <class U>
  explicit constexpr SanitizingAllocator(
      const SanitizingAllocator<U>&) noexcept {}

  ABSL_MUST_USE_RESULT T* allocate(std::size_t n) {
    return SanitizingAllocatorImpl<T>::allocate(n);
  }

  void deallocate(T* ptr, std::size_t n) noexcept {
    SanitizingAllocatorImpl<T>::deallocate(ptr, n);
  }

  // Allocator requirements mandate definition of eq and neq operators
  bool operator==(const SanitizingAllocator&) { return true; }
  bool operator!=(const SanitizingAllocator&) { return false; }
};

}  // namespace internal
}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_SECRET_DATA_INTERNAL_H_
