// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
#ifndef TINK_SUBTLE_PRF_STREAMING_PRF_H_
#define TINK_SUBTLE_PRF_STREAMING_PRF_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/input_stream.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Streaming API interface for PseudoRandomFunctions.
//
// Implementations of this are indistinguishable from true random functions.
//
// For a formal description of the security properties, see the documentation in
// the corresponding Java class.
class StreamingPrf {
 public:
  // Returns a stream of pseudorandom bytes for this input. Calling Get twice
  // with the same input will return a copy of the same input stream.
  virtual std::unique_ptr<InputStream> ComputePrf(
      absl::string_view input) const = 0;

  virtual ~StreamingPrf() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_PRF_STREAMING_PRF_H_
