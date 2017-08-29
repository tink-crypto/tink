// Copyright 2017 Google Inc.
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

#ifndef TINK_UTIL_MAKE_UNIQUE_H_
#define TINK_UTIL_MAKE_UNIQUE_H_

#include <memory>

namespace crypto {
namespace tink {
namespace util {

// C++14 make_unique.
// This is present in clang with -std=c++14 (in <memory>), but not
// otherwise. So define it for standard versions prior to c++14 here.
// (copied from https://github.com/google/xrtl/)
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
#if _LIBCPP_STD_VER >= 14
  return std::make_unique<T>(std::forward<Args>(args)...);
#else
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
#endif
}

// Transfers ownership of a raw pointer to a std::unique_ptr of deduced type.
// (copied from https://github.com/tensorflow/tensorflow/)
template <typename T>
std::unique_ptr<T> wrap_unique(T* ptr) {
  static_assert(
      !std::is_array<T>::value || std::extent<T>::value != 0,
      "types T[0] or T[] are unsupported");
  return std::unique_ptr<T>(ptr);
}

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_MAKE_UNIQUE_H_
