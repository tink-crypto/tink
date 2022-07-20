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

#ifndef TINK_PYTHON_CC_OUTPUT_STREAM_ADAPTER_H_
#define TINK_PYTHON_CC_OUTPUT_STREAM_ADAPTER_H_

#include <memory>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Adapts an OutputStream for use in Python.
class OutputStreamAdapter {
 public:
  explicit OutputStreamAdapter(std::unique_ptr<OutputStream> stream)
      : stream_(std::move(stream)) {}

  // Writes 'data' to the underlying OutputStream and returns the number of
  // bytes written, which may be less than size of 'data'.
  // It repeatedly calls Next() as long as it returns positive values. This
  // ensures that in the usual case when we can write all of 'data' the user can
  // call Write() once and no unnecessary copies are made.
  util::StatusOr<int64_t> Write(absl::string_view data);

  // Closes the underlying OutputStream.
  util::Status Close();

 private:
  std::unique_ptr<OutputStream> stream_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PYTHON_CC_OUTPUT_STREAM_ADAPTER_H_
