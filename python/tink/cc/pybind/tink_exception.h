// Copyright 2022 Google LLC
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

#ifndef TINK_PYTHON_TINK_CC_PYBIND_TINK_EXCEPTION_H_
#define TINK_PYTHON_TINK_CC_PYBIND_TINK_EXCEPTION_H_

#include <exception>
#include <string>
#include <utility>

#include "tink/util/status.h"

namespace pybind11 {
namespace google_tink {

class TinkException : public std::exception {
 public:
  explicit TinkException(const crypto::tink::util::Status& status)
      : error_code_(static_cast<int>(status.code())),
        what_(status.ToString()) {}

  int error_code() const {
    return error_code_;
  }

  const char* what() const noexcept override {
    return what_.c_str();
  }

 private:
  int error_code_;
  std::string what_;
};

}  // namespace google_tink
}  // namespace pybind11

#endif  // TINK_PYTHON_TINK_CC_PYBIND_TINK_EXCEPTION_H_
