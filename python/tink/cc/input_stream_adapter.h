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

#ifndef TINK_PYTHON_CC_INPUT_STREAM_ADAPTER_H_
#define TINK_PYTHON_CC_INPUT_STREAM_ADAPTER_H_

#include <memory>
#include <string>
#include <utility>

#include "tink/input_stream.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Adapts an InputStream for use in Python.
class InputStreamAdapter {
 public:
  explicit InputStreamAdapter(std::unique_ptr<InputStream> stream)
      : stream_(std::move(stream)) {}

  // Reads at most 'size' bytes from the underlying InputStream using only one
  // call to Next().
  // If size is negative, all bytes that Next() gives are returned.
  // Returns OUT_OF_RANGE status if the stream is already at EOF.
  util::StatusOr<std::string> Read(int64_t size);

 private:
  std::unique_ptr<InputStream> stream_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PYTHON_CC_INPUT_STREAM_ADAPTER_H_
