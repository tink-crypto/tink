// Copyright 2019 Google LLC
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

#ifndef TINK_SUBTLE_STREAMING_MAC_IMPL_H_
#define TINK_SUBTLE_STREAMING_MAC_IMPL_H_

#include <memory>
#include <string>
#include <utility>

#include "tink/streaming_mac.h"
#include "tink/subtle/mac/stateful_mac.h"

namespace crypto {
namespace tink {
namespace subtle {

class StreamingMacImpl : public StreamingMac {
 public:
  // Constructor
  explicit StreamingMacImpl(std::unique_ptr<StatefulMacFactory> mac_factory)
      : mac_factory_(std::move(mac_factory)) {}

  // Implement streaming mac class functions
  // Returns an ComputeMacOutputStream, which when closed will return the
  // message authentication code (MAC) of the data put into the stream.
  util::StatusOr<std::unique_ptr<OutputStreamWithResult<std::string>>>
  NewComputeMacOutputStream() const override;

  // Returns an VerifyMacOutputStream which verifies if 'mac' is a correct
  // message authentication code (MAC) for the data written to it.
  util::StatusOr<std::unique_ptr<OutputStreamWithResult<util::Status>>>
  NewVerifyMacOutputStream(const std::string& mac_value) const override;

 private:
  std::unique_ptr<StatefulMacFactory> mac_factory_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_STREAMING_MAC_IMPL_H_
