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

// Utility classes functions for util::Status objects.
// These are needed by both the status module and casters.
#ifndef TINK_PYTHON_CC_PYBIND_STATUS_UTILS_H_
#define TINK_PYTHON_CC_PYBIND_STATUS_UTILS_H_

#include <pybind11/pybind11.h>

#include <exception>
#include <functional>
#include <string>
#include <utility>

#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace pybind11 {
namespace google_tink {

namespace util = crypto::tink::util;

void ImportStatusModule();

// Wrapper type to signal to the type_caster that a non-ok status should not
// be converted into an object rather than a thrown exception.
template <typename StatusType>
struct NoThrowStatus {
  explicit NoThrowStatus(StatusType status_in)
      : status(std::forward<StatusType>(status_in)) {}
  StatusType status;
};

// Convert a util::Status(Or) into a NoThrowStatus.
template <typename StatusType>
NoThrowStatus<StatusType> DoNotThrowStatus(StatusType status) {
  return NoThrowStatus<StatusType>(std::forward<StatusType>(status));
}
// Convert a function returning a util::Status(Or) into a function
// returning a NoThrowStatus.
template <typename StatusType, typename... Args>
std::function<NoThrowStatus<StatusType>(Args...)> DoNotThrowStatus(
    std::function<StatusType(Args...)> f) {
  return [f](Args... args) {
    return NoThrowStatus<StatusType>(
        std::forward<StatusType>(f(std::forward<Args>(args)...)));
  };
}
template <typename StatusType, typename... Args>
std::function<NoThrowStatus<StatusType>(Args...)> DoNotThrowStatus(
    StatusType (*f)(Args...)) {
  return [f](Args... args) {
    return NoThrowStatus<StatusType>(
        std::forward<StatusType>(f(std::forward<Args>(args)...)));
  };
}
template <typename StatusType, typename Class, typename... Args>
std::function<NoThrowStatus<StatusType>(Class*, Args...)> DoNotThrowStatus(
    StatusType (Class::*f)(Args...)) {
  return [f](Class *c, Args... args) {
    return NoThrowStatus<StatusType>(
        std::forward<StatusType>((c->*f)(std::forward<Args>(args)...)));
  };
}
template <typename StatusType, typename Class, typename... Args>
std::function<NoThrowStatus<StatusType>(const Class*, Args...)>
DoNotThrowStatus(StatusType (Class::*f)(Args...) const) {
  return [f](const Class* c, Args... args) {
    return NoThrowStatus<StatusType>(
        std::forward<StatusType>((c->*f)(std::forward<Args>(args)...)));
  };
}

// Exception to throw when we return a non-ok status.
class StatusNotOk : public std::exception {
 public:
  StatusNotOk(util::Status&& status)
      : status_(std::move(status)), what_(status_.ToString()) {}
  StatusNotOk(const util::Status& status)
      : status_(status), what_(status_.ToString()) {}
  const util::Status& status() const { return status_; }
  const char* what() const noexcept override { return what_.c_str(); }

 private:
  util::Status status_;
  std::string what_;
};

}  // namespace google_tink
}  // namespace pybind11

#endif  // TINK_PYTHON_CC_PYBIND_STATUS_UTILS_H_
