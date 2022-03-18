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

#ifndef TINK_UTIL_SECRET_DATA_H_
#define TINK_UTIL_SECRET_DATA_H_

#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "absl/strings/string_view.h"
#include "tink/util/secret_data_internal.h"

namespace crypto {
namespace tink {
namespace util {

// Stores secret (sensitive) data and makes sure it's marked as such and
// destroyed in a safe way.
// This should be the first choice when handling key/key derived values.
//
// Example:
// class MyCryptoPrimitive {
//  public:
//   MyCryptoPrimitive(absl::string_view key_value) :
//     key_(SecretDataFromStringView(key_value)) {}
//   [...]
//  private:
//   const util::SecretData key_;
// }
using SecretData = std::vector<uint8_t, internal::SanitizingAllocator<uint8_t>>;

// Stores secret (sensitive) object and makes sure it's marked as such and
// destroyed in a safe way.
// SecretUniquePtr MUST be constructed using MakeSecretUniquePtr function.
// Generally SecretUniquePtr should be used iff SecretData is unsuitable.
//
// Example:
// class MyCryptoPrimitive {
//  public:
//   MyEncryptionPrimitive(absl::string_view key_value) {
//     AES_set_encrypt_key(key_value.data(), key_value.size() * 8, key_.get());
//   }
//   [...]
//  private:
//   util::SecretUniquePtr<AES_KEY> key_ = util::MakeSecretUniquePtr<AES_KEY>();
// }
//
// NOTE: SecretUniquePtr<T> will only protect the data which is stored in the
// memory which a T object takes on the stack. In particular, std::string and
// std::vector SHOULD NOT be used as arguments of T: they allocate memory
// on the heap, and hence the data stored in them will NOT be protected.
template <typename T>
class SecretUniquePtr {
 private:
  using Value = std::unique_ptr<T, internal::SanitizingDeleter<T>>;

 public:
  using pointer = typename Value::pointer;
  using element_type = typename Value::element_type;
  using deleter_type = typename Value::deleter_type;

  SecretUniquePtr() {}

  pointer get() const { return value_.get(); }
  deleter_type& get_deleter() { return value_.get_deleter(); }
  const deleter_type& get_deleter() const { return value_.get_deleter(); }
  void swap(SecretUniquePtr& other) { value_.swap(other.value_); }
  void reset() { value_.reset(); }

  typename std::add_lvalue_reference<T>::type operator*() const {
    return value_.operator*();
  }
  pointer operator->() const { return value_.operator->(); }
  explicit operator bool() const { return value_.operator bool(); }

 private:
  template <typename S, typename... Args>
  friend SecretUniquePtr<S> MakeSecretUniquePtr(Args&&... args);
  explicit SecretUniquePtr(Value&& value) : value_(std::move(value)) {}
  Value value_;
};

template <typename T, typename... Args>
SecretUniquePtr<T> MakeSecretUniquePtr(Args&&... args) {
  T* ptr = internal::SanitizingAllocator<T>().allocate(1);
  new (ptr)
      T(std::forward<Args>(args)...);  // Invoke constructor "placement new"
  return SecretUniquePtr<T>({ptr, internal::SanitizingDeleter<T>()});
}

// Convenience conversion functions
inline absl::string_view SecretDataAsStringView(const SecretData& secret) {
  return {reinterpret_cast<const char*>(secret.data()), secret.size()};
}

inline SecretData SecretDataFromStringView(absl::string_view secret) {
  return {secret.begin(), secret.end()};
}

template <typename T>
class SecretValue {
 public:
  explicit SecretValue(T t = T())
      : ptr_(MakeSecretUniquePtr<T>(std::move(t))) {}

  SecretValue(const SecretValue& other) {
    ptr_ = MakeSecretUniquePtr<T>(*other.ptr_);
  }

  SecretValue& operator=(const SecretValue& other) {
    *ptr_ = *other.ptr_;
    return *this;
  }

  T& value() { return *ptr_; }
  const T& value() const { return *ptr_; }

 private:
  SecretUniquePtr<T> ptr_;
};

inline void SafeZeroMemory(void* ptr, std::size_t size) {
  internal::SafeZeroMemory(ptr, size);
}

inline void SafeZeroString(std::string* str) {
  SafeZeroMemory(&(*str)[0], str->size());
}

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_SECRET_DATA_H_
