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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_KEYDERIVATION_KEYSET_DERIVER_WRAPPER_H_
#define TINK_KEYDERIVATION_KEYSET_DERIVER_WRAPPER_H_

#include <memory>

#include "tink/keyderivation/keyset_deriver.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// A KeysetDeriverWrapper wraps the KeysetDeriver primitive.
//
// The wrapper derives a key from each key in a keyset. It returns the resulting
// keys in a new keyset. Each of the derived keys inherits key_id, status, and
// output_prefix_type from the key from which it was derived.
class KeysetDeriverWrapper
    : public PrimitiveWrapper<KeysetDeriver, KeysetDeriver> {
 public:
  crypto::tink::util::StatusOr<std::unique_ptr<KeysetDeriver>> Wrap(
      std::unique_ptr<PrimitiveSet<KeysetDeriver>> deriver_set) const override;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_KEYSET_DERIVER_WRAPPER_H_
