// Copyright 2017 Google Inc.
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

#ifndef TINK_STREAMING_MAC_H_
#define TINK_STREAMING_MAC_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/output_stream_with_result.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Interface for Streaming MACs (Message Authentication Codes).
// This interface should be used for authentication only, and not for other
// purposes (e.g., it should not be used to generate pseudorandom bytes).
class StreamingMac {
 public:
  // Returns an ComputeMacOutputStream, which when closed will return the
  // message authentication code (MAC) of the data put into the stream.
  virtual util::StatusOr<std::unique_ptr<OutputStreamWithResult<std::string>>>
  NewComputeMacOutputStream() const = 0;

  // Returns an VerifyMacOutputStream which verifies if 'mac' is a correct
  // message authentication code (MAC) for the data written to it.
  virtual util::StatusOr<std::unique_ptr<OutputStreamWithResult<util::Status>>>
  NewVerifyMacOutputStream(const std::string& mac_value) const = 0;

  virtual ~StreamingMac() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMING_MAC_H_
