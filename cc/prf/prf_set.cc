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

#include "tink/prf/prf_set.h"

namespace crypto {
namespace tink {

util::StatusOr<std::string> PrfSet::ComputePrimary(absl::string_view input,
                                                   size_t output_length) const {
  auto prfs = GetPrfs();
  auto prf_it = prfs.find(GetPrimaryId());
  if (prf_it == prfs.end()) {
    return util::Status(util::error::INTERNAL,
                        "PrfSet has no PRF for primary ID.");
  }
  return prf_it->second->Compute(input, output_length);
}

}  // namespace tink
}  // namespace crypto
