// Copyright 2020 Google LLC
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
#ifndef TINK_SUBTLE_PRF_PRF_SET_UTIL_H_
#define TINK_SUBTLE_PRF_PRF_SET_UTIL_H_

#include <memory>

#include "tink/prf/prf_set.h"
#include "tink/subtle/mac/stateful_mac.h"
#include "tink/subtle/prf/streaming_prf.h"

namespace crypto {
namespace tink {
namespace subtle {

// Creates a Prf from a StreamingPrf, taking ownership of the StreamingPrf.
std::unique_ptr<Prf> CreatePrfFromStreamingPrf(
    std::unique_ptr<StreamingPrf> streaming_prf);
// Creates a Prf from a StatefulMacFactory, taking ownership of the factory.
// Note that this should only be used with StatefulMacs that actually are a Prf,
// like HMAC and CMAC and not with any MACs that are non-deterministic or that
// do not produce output indistinguishable from random numbers.
std::unique_ptr<Prf> CreatePrfFromStatefulMacFactory(
    std::unique_ptr<StatefulMacFactory> mac_factory);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_PRF_PRF_SET_UTIL_H_
