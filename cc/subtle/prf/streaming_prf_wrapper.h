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

#ifndef TINK_SUBTLE_PRF_STREAMING_PRF_WRAPPER_H_
#define TINK_SUBTLE_PRF_STREAMING_PRF_WRAPPER_H_

#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Wraps a set of StreamingPrf-instances containing a single StreamingPrf with a
// raw key into a StreamingPrf (essentially just returning the initial prf).
//
// It is unclear how key rotation should work for Prfs; we use this one to
// produce a single one in case the keyset is compatible, and fail otherwise.
class StreamingPrfWrapper
    : public PrimitiveWrapper<StreamingPrf, StreamingPrf> {
 public:
  util::StatusOr<std::unique_ptr<StreamingPrf>> Wrap(
      std::unique_ptr<PrimitiveSet<StreamingPrf>> streaming_prf_set)
      const override;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_PRF_STREAMING_PRF_WRAPPER_H_
