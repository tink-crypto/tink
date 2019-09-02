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

#ifndef TINK_PYTHON_CC_SIMPLE_OUTPUT_STREAM_H_
#define TINK_PYTHON_CC_SIMPLE_OUTPUT_STREAM_H_

#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// A simple interface for an output stream like object which can be used to go
// from Python to C++ via CLIF and vice versa.
class SimpleOutputStream {
 public:
  // Writes 'data' to the underlying stream and returns the number of bytes
  // written, which can be less than the size of 'data'.
  virtual util::StatusOr<int> Write(absl::string_view data) = 0;

  // Closes the underlying stream.
  virtual util::Status Close() = 0;

  // Returns the total number of bytes written.
  virtual int64_t Position() const = 0;

  virtual ~SimpleOutputStream() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PYTHON_CC_SIMPLE_OUTPUT_STREAM_H_
