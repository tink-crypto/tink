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

#ifndef TINK_PYTHON_CC_PYTHON_FILE_OBJECT_ADAPTER_H_
#define TINK_PYTHON_CC_PYTHON_FILE_OBJECT_ADAPTER_H_

#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Adapts a Python file object for use in C++.
// This is wrapped with pybind and implemented in Python.
class PythonFileObjectAdapter {
 public:
  // Writes 'data' to the underlying Python file object and returns the number
  // of bytes written, which can be less than the size of 'data'.
  virtual util::StatusOr<int> Write(absl::string_view data) = 0;

  // Closes the underlying Python file object.
  virtual util::Status Close() = 0;

  // Reads at most 'size' bytes from the underlying Python file object. Returns
  // UNKNOWN status with error message that contains "EOFError" if the file
  // object is alreday at EOF.
  virtual util::StatusOr<std::string> Read(int size) = 0;

  virtual ~PythonFileObjectAdapter() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PYTHON_CC_PYTHON_FILE_OBJECT_ADAPTER_H_
