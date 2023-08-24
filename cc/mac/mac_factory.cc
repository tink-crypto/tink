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

#include "tink/mac/mac_factory.h"

#include <memory>

#include "tink/mac.h"
#include "tink/mac/mac_wrapper.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
// TINK-PENDING-REMOVAL-IN-3.0.0-START
// static
util::StatusOr<std::unique_ptr<Mac>> MacFactory::GetPrimitive(
    const KeysetHandle& keyset_handle) {
  util::Status status =
      Registry::RegisterPrimitiveWrapper(absl::make_unique<MacWrapper>());
  if (!status.ok()) {
    return status;
  }
  return keyset_handle.GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
}

// static
util::StatusOr<std::unique_ptr<Mac>> MacFactory::GetPrimitive(
    const KeysetHandle& keyset_handle,
    const KeyManager<Mac>* custom_key_manager) {
  util::Status status =
      Registry::RegisterPrimitiveWrapper(absl::make_unique<MacWrapper>());
  if (!status.ok()) {
    return status;
  }
  return keyset_handle.GetPrimitive<Mac>(custom_key_manager);
}
// TINK-PENDING-REMOVAL-IN-3.0.0-END
// NOLINTEND(whitespace/line_length)

}  // namespace tink
}  // namespace crypto
