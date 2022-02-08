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

#ifndef TINK_MAC_H_
#define TINK_MAC_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Interface for MACs (Message Authentication Codes).
// This interface should be used for authentication only, and not for other
// purposes (e.g., it should not be used to generate pseudorandom bytes).
class Mac {
 public:
  // Computes and returns the message authentication code (MAC) for 'data'.
  virtual crypto::tink::util::StatusOr<std::string> ComputeMac(
      absl::string_view data) const = 0;

  // Verifies if 'mac' is a correct authentication code (MAC) for 'data'.
  // Returns Status::OK if 'mac' is correct, and a non-OK-Status otherwise.
  virtual crypto::tink::util::Status VerifyMac(
      absl::string_view mac_value,
      absl::string_view data) const = 0;

  virtual ~Mac() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_H_
