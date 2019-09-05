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

#ifndef TINK_PYTHON_CC_OUTPUT_STREAM_ADAPTER_H_
#define TINK_PYTHON_CC_OUTPUT_STREAM_ADAPTER_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/python/cc/simple_output_stream.h"

namespace crypto {
namespace tink {

// Wraps an OutputStream to SimpleOutputStream for use in Python.
class OutputStreamAdapter : public SimpleOutputStream {
 public:
  explicit OutputStreamAdapter(std::unique_ptr<OutputStream> stream)
      : stream_(std::move(stream)) {}

  // Writes 'data' to the underlying OutputStream using only one call to Next(),
  // and returns the number of bytes written. It is possible that only a part of
  // 'data' was written.
  util::StatusOr<int> Write(absl::string_view data) override;

  util::Status Close() override;

  int64_t Position() const override;

 private:
  std::unique_ptr<OutputStream> stream_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PYTHON_CC_OUTPUT_STREAM_ADAPTER_H_
