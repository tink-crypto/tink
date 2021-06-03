// Copyright 2013 Google Inc. All Rights Reserved.
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

#ifndef TINK_UTIL_STATUSOR_H_
#define TINK_UTIL_STATUSOR_H_

#include <cstdlib>
#include <iostream>
#include <utility>

#include "absl/status/statusor.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace util {

#ifndef CPP_TINK_TEMPORARY_STATUS_MUST_NOT_USE_RESULT
template <typename T>
class ABSL_MUST_USE_RESULT StatusOr;
#endif

// TODO(b/122292096): Migrate this to absl::StatusOr
// A StatusOr holds a Status (in the case of an error), or a value T.
template <typename T>
class StatusOr {
 public:
  using type = T;
  // Has status UNKNOWN.
  inline StatusOr();

  // Builds from a non-OK status. Crashes if an OK status is specified.
  inline StatusOr(const ::crypto::tink::util::Status& status);  // NOLINT

  // Builds from the specified value.
  inline StatusOr(const T& value);  // NOLINT
  inline StatusOr(T&& value);       // NOLINT

  // Copy constructor.
  inline StatusOr(const StatusOr& other);

  // Move constructor.
  inline StatusOr(StatusOr&& other);

  // Conversion copy constructor, T must be copy constructible from U.
  template <typename U>
  inline StatusOr(const StatusOr<U>& other);

  // Assignment operator.
  inline const StatusOr& operator=(const StatusOr& other);

  // Conversion assignment operator, T must be assignable from U
  template <typename U>
  inline const StatusOr& operator=(const StatusOr<U>& other);

  // Accessors.
  inline const ::crypto::tink::util::Status& status() const {
    return status_;
  }

  // Shorthand for status().ok().
  inline bool ok() const {
    return status_.ok();
  }

  // Returns value or crashes if ok() is false.
  inline const T& ValueOrDie() const& {
    EnsureOk();
    return *value_;
  }
  inline T& ValueOrDie() & {
    EnsureOk();
    return *value_;
  }
  inline const T&& ValueOrDie() const&& {
    EnsureOk();
    return *std::move(value_);
  }
  inline T&& ValueOrDie() && {
    EnsureOk();
    return *std::move(value_);
  }

  // Implicitly convertible to absl::StatusOr. Implicit conversions explicitly
  // allowed by style arbiter waiver in cl/351594378.
  operator ::absl::StatusOr<T>() const&;  // NOLINT
  operator ::absl::StatusOr<T>() &&;      // NOLINT

  // Returns value or crashes if ok() is false.
  inline const T& operator*() const& {
    EnsureOk();
    return *value_;
  }

  inline T& operator*() & {
    EnsureOk();
    return *value_;
  }

  inline T&& operator*() && {
    EnsureOk();
    return *std::move(value_);
  }

  inline const T&& operator*() const&& {
    EnsureOk();
    return *std::move(value_);
  }

  // Returns reference to value or crashes if ok() is false.
  T* operator->() {
    EnsureOk();
    return &(value_.value());
  }

  const T* operator->() const {
    EnsureOk();
    return &(value_.value());
  }

  template <typename U>
  friend class StatusOr;

 private:
  void EnsureOk() const {
    if (ABSL_PREDICT_FALSE(!ok())) {
      std::cerr << "Attempting to fetch value of non-OK StatusOr\n";
      std::cerr << status() << std::endl;
      std::_Exit(1);
    }
  }

  Status status_;
  absl::optional<T> value_;
};

// Implementation.

template <typename T>
inline StatusOr<T>::StatusOr()
    : status_(::crypto::tink::util::error::UNKNOWN, "") {
}

template <typename T>
inline StatusOr<T>::StatusOr(
    const ::crypto::tink::util::Status& status) : status_(status) {
  if (status.ok()) {
    std::cerr << "::crypto::tink::util::OkStatus() "
              << "is not a valid argument to StatusOr\n";
    std::_Exit(1);
  }
}

template <typename T>
inline StatusOr<T>::StatusOr(const T& value) : value_(value) {
}

template <typename T>
inline StatusOr<T>::StatusOr(T&& value) : value_(std::move(value)) {
}

template <typename T>
inline StatusOr<T>::StatusOr(const StatusOr& other)
    : status_(other.status_), value_(other.value_) {
}

template <typename T>
inline StatusOr<T>::StatusOr(StatusOr&& other)
    : status_(other.status_), value_(std::move(other.value_)) {
}

template <typename T>
template <typename U>
inline StatusOr<T>::StatusOr(const StatusOr<U>& other)
    : status_(other.status_), value_(other.value_) {
}

template <typename T>
inline const StatusOr<T>& StatusOr<T>::operator=(const StatusOr& other) {
  status_ = other.status_;
  if (status_.ok()) {
    value_ = *other.value_;
  } else {
    value_ = absl::nullopt;
  }
  return *this;
}

template <typename T>
template <typename U>
inline const StatusOr<T>& StatusOr<T>::operator=(const StatusOr<U>& other) {
  status_ = other.status_;
  if (status_.ok()) {
    value_ = *other.value_;
  } else {
    value_ = absl::nullopt;
  }
  return *this;
}

template <typename T>
StatusOr<T>::operator ::absl::StatusOr<T>() const& {
  if (!ok()) return ::absl::Status(status_);
  return *value_;
}

template <typename T>
StatusOr<T>::operator ::absl::StatusOr<T>() && {
  if (!ok()) return ::absl::Status(std::move(status_));
  return std::move(*value_);
}


}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_STATUSOR_H_
