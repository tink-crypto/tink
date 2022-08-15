// Copyright 2021 Google LLC
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

#ifndef TINK_AEAD_INTERNAL_ZERO_COPY_AEAD_WRAPPER_H_
#define TINK_AEAD_INTERNAL_ZERO_COPY_AEAD_WRAPPER_H_

#include <memory>

#include "tink/aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Wraps a set of ZeroCopyAead-instances that correspond to a keyset and
// combines them into a single Aead-primitive that uses the provided instances,
// depending on the context:
//   * ZeroCopyAeadSetWrapper::Encrypt(...) uses the primary instance from the
//   set.
//   * ZeroCopyAeadSetWrapper::Decrypt(...) uses the instance that matches the
//   ciphertext prefix.
class ZeroCopyAeadWrapper : public PrimitiveWrapper<ZeroCopyAead, Aead> {
 public:
  // Returns an Aead-primitive that uses ZeroCopyAead-instances provided in
  // 'aead_set', which must be non-NULL and must contain a primary instance.
  util::StatusOr<std::unique_ptr<Aead>> Wrap(
      std::unique_ptr<PrimitiveSet<ZeroCopyAead>> aead_set) const override;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AEAD_WRAPPER_H_
