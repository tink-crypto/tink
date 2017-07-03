// Copyright 2017 Google Inc.
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

#ifndef TINK_HYBRID_HYBRID_ENCRYPT_FACTORY_H_
#define TINK_HYBRID_HYBRID_ENCRYPT_FACTORY_H_

#include "cc/hybrid_encrypt.h"
#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// HybridEncryptFactory allows for obtaining an HybridEncrypt primitive
// from a KeysetHandle.
//
// HybridEncryptFactory gets primitives from the Registry, which can
// be initialized via convenience methods from HybridEncryptConfig-class.
// Here is an example how one can obtain and use a HybridEncrypt primitive:
//
//   HybridEncryptConfig.RegisterStandardKeyTypes();
//   KeysetHandle keyset_handle = ...;
//   std::unique_ptr<HybridEncrypt> hybrid_encrypt = std::move(
//           HybridEncryptFactory.GetPrimitive(keyset_handle).ValueOrDie());
//   string plaintext = ...;
//   string context_info = ...;
//   string ciphertext =
//       hybrid_encrypt.Encrypt(plaintext, context_info).ValueOrDie();
//
class HybridEncryptFactory {
 public:
  // Returns a HybridEncrypt-primitive that uses key material from the keyset
  // specified via 'keyset_handle'.
  static util::StatusOr<std::unique_ptr<HybridEncrypt>> GetPrimitive(
      const KeysetHandle& keyset_handle);

  // Returns a HybridEncrypt-primitive that uses key material from the keyset
  // specified via 'keyset_handle' and is instantiated by the given
  // 'custom_key_manager' (instead of the key manager from the Registry).
  static util::StatusOr<std::unique_ptr<HybridEncrypt>> GetPrimitive(
      const KeysetHandle& keyset_handle,
      const KeyManager<HybridEncrypt>* custom_key_manager);

 private:
  HybridEncryptFactory() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_HYBRID_ENCRYPT_FACTORY_H_
