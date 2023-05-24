// Copyright 2018 Google Inc.
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

#ifndef TINK_PRIMITIVE_WRAPPER_H_
#define TINK_PRIMITIVE_WRAPPER_H_

#include <memory>

#include "tink/primitive_set.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// A PrimitiveWrapper knows how to wrap multiple instances of a primitive to
// a single instance, enabling key-rotation. It requires a
// PrimitiveSet<Primitive> and wraps it into a single primitive.
//
// PrimitiveWrappers need to be written for every new primitive. They can be
// registered in the registry to be fully integrated in Tink.
template <typename InputPrimitiveParam, typename PrimitiveParam>
class PrimitiveWrapper {
 public:
  virtual ~PrimitiveWrapper() = default;

  // Useful when writing templated code.
  using InputPrimitive = InputPrimitiveParam;
  using Primitive = PrimitiveParam;

  virtual crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> Wrap(
      std::unique_ptr<PrimitiveSet<InputPrimitive>> primitive_set) const = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRIMITIVE_WRAPPER_H_
