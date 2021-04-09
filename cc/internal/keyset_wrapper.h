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
#ifndef TINK_INTERNAL_KEYSET_WRAPPER_H_
#define TINK_INTERNAL_KEYSET_WRAPPER_H_

#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// A Keyset wrapper wraps a Tink Keyset into a set of primitives. This is a
// Tink internal object, which is created from a PrimitiveWrapper.
//
// The KeysetWrapper is used because the only moment during compilation in which
// the registry knows the input primitive type of a PrimitiveWrapper<P, Q> is
// when RegisterPrimitiveWrapper(transforming_wrapper) is called. (There, the
// compiler infers the template arguments. This means that all the work which
// handles Q needs to be done in that compilation unit, and when creating the
// primitive we cannot refer to Q.
//
// Hence, when registering the object, we first use type erasure to forget about
// Q and create a subclass (KeysetWrapperImpl<P,Q>) of this object.
template <typename Primitive>
class KeysetWrapper {
 public:
  virtual ~KeysetWrapper() {}

  virtual crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> Wrap(
      const google::crypto::tink::Keyset& keyset) const = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_KEYSET_WRAPPER_H_
