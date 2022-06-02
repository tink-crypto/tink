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

#ifndef TINK_CHUNKED_MAC_H_
#define TINK_CHUNKED_MAC_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Interface for a single Chunked MAC computation.
class ChunkedMacComputation {
 public:
  // Incrementally processes input `data` to update the internal state of the
  // MAC computation.
  virtual util::Status Update(absl::string_view data) = 0;

  // Finalizes the MAC computation and returns the authentication tag.
  // After this method has been called, this object can no longer be used.
  virtual util::StatusOr<std::string> ComputeMac() = 0;

  virtual ~ChunkedMacComputation() = default;
};

// Interface for a single Chunked MAC verification.
class ChunkedMacVerification {
 public:
  // Incrementally processes input `data` to update the internal state of the
  // MAC verification.
  virtual util::Status Update(absl::string_view data) = 0;

  // Finalizes the MAC computation and returns OK if the tag is successfully
  // verified.  Otherwise, returns an error status.  After this method has been
  // called, this object can no longer be used.
  virtual util::Status VerifyMac() = 0;

  virtual ~ChunkedMacVerification() = default;
};

// Interface for Chunked MACs (Message Authentication Codes).
// This interface should only be used for authentication.  It should NOT
// be used for other purposes (e.g., generating pseudorandom bytes).
class ChunkedMac {
 public:
  // Creates an instance of a single Chunked MAC computation.  Note that a
  // `ChunkedMac` object does not need to outlive the `ChunkedMacComputation`
  // objects that it creates.
  virtual util::StatusOr<std::unique_ptr<ChunkedMacComputation>>
  CreateComputation() const = 0;

  // Creates an instance of a single Chunked MAC verification.  Note that a
  // `ChunkedMac` object does not need to outlive the `ChunkedMacVerification`
  // objects that it creates.
  virtual util::StatusOr<std::unique_ptr<ChunkedMacVerification>>
  CreateVerification(absl::string_view tag) const = 0;

  virtual ~ChunkedMac() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CHUNKED_MAC_H_
