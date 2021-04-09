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
#ifndef TINK_PRF_PRF_SET_WRAPPER_H_
#define TINK_PRF_PRF_SET_WRAPPER_H_

#include <cstdint>
#include <memory>

#include "tink/prf/prf_set.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Wraps a set of PrfSet-instances that correspond to a keyset,
// and combines them into a single PrfSet-primitive, that uses the provided
// instances, by using the keysets key ID as Prf ID and computing the union of
// the provided PRFs.
class PrfSetWrapper : public PrimitiveWrapper<Prf, PrfSet> {
 public:
  util::StatusOr<std::unique_ptr<PrfSet>> Wrap(
      std::unique_ptr<PrimitiveSet<Prf>> prf_set) const override;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_PRF_SET_WRAPPER_H_
