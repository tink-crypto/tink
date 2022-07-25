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

#ifndef TINK_CHUNKEDMAC_INTERNAL_CHUNKED_MAC_WRAPPER_H_
#define TINK_CHUNKEDMAC_INTERNAL_CHUNKED_MAC_WRAPPER_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/chunked_mac.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Wraps a set of ChunkedMac-instances that correspond to a keyset,
// and combines them into a single ChunkedMac-primitive, that uses the provided
// instances, depending on the context:
//   * ChunkedMac::CreateComputation(...) uses the primary instance from the
//     set.
//   * ChunkedMac::CreateVerification(...) uses all instances with matching
//     MAC prefixes.
class ChunkedMacWrapper : public PrimitiveWrapper<ChunkedMac, ChunkedMac> {
 public:
  util::StatusOr<std::unique_ptr<ChunkedMac>> Wrap(
      std::unique_ptr<PrimitiveSet<ChunkedMac>> mac_set) const override;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_CHUNKEDMAC_INTERNAL_CHUNKED_MAC_WRAPPER_H_
