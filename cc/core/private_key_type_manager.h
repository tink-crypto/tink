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
///////////////////////////////////////////////////////////////////////////////
#ifndef TINK_CORE_PRIVATE_KEY_TYPE_MANAGER_H_
#define TINK_CORE_PRIVATE_KEY_TYPE_MANAGER_H_

#include <memory>

#include "tink/core/key_type_manager.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

template <typename KeyProto, typename KeyFormatProto, typename PublicKeyProto,
          typename... Primitives>
class PrivateKeyTypeManager;

// A PrivateKeyTypeManager is an extension of KeyTypeManager. One
// should implement this in case there is a public key corresponding to the
// private key managed by this manager.
// Hence, in addition to the tasks a KeyTypeManager does, in order to
// implement a PrivateKeyTypeManager one needs to provide a function
// StatusOr<PublicKeyProto> GetPublicKey(const KeyProto& private_key) const = 0;
template <typename KeyProto, typename KeyFormatProto, typename PublicKeyProto,
          typename... Primitives>
class PrivateKeyTypeManager<KeyProto, KeyFormatProto, PublicKeyProto,
                            List<Primitives...>>
    : public KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>> {
 public:
  explicit PrivateKeyTypeManager(
      std::unique_ptr<typename KeyTypeManager<KeyProto, KeyFormatProto,
                                              List<Primitives...>>::
                          template PrimitiveFactory<Primitives>>... primitives)
      : KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>(
            std::move(primitives)...) {}

  virtual crypto::tink::util::StatusOr<PublicKeyProto> GetPublicKey(
      const KeyProto& private_key) const = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_PRIVATE_KEY_TYPE_MANAGER_H_
