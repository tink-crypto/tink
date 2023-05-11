// Copyright 2023 Google Inc.
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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_KEYDERIVATION_INTERNAL_KEYSET_DERIVER_SET_WRAPPER_IMPL_H_
#define TINK_KEYDERIVATION_INTERNAL_KEYSET_DERIVER_SET_WRAPPER_IMPL_H_

#include <vector>

#include "tink/keyderivation/keyset_deriver.h"
#include "tink/primitive_set.h"

namespace crypto {
namespace tink {
namespace internal {

class KeysetDeriverSetWrapperImpl {
 public:
  // Stores PrfBasedDeriverKey entries so key derivation preserves the original
  // keyset key order.
  static inline std::vector<PrimitiveSet<KeysetDeriver>::Entry<KeysetDeriver>*>
  get_all_in_keyset_order(const PrimitiveSet<KeysetDeriver>& primitive_set) {
    absl::MutexLockMaybe lock(primitive_set.primitives_mutex_.get());
    std::vector<PrimitiveSet<KeysetDeriver>::Entry<KeysetDeriver>*> result =
        primitive_set.ordered_keyset_deriver_primitives_;
    return result;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_INTERNAL_KEYSET_DERIVER_SET_WRAPPER_IMPL_H_
