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
// HybridEncryptFactory allows obtaining a primitive from a KeysetHandle.
//
// HybridEncryptFactory gets primitives from the Registry. The factory allows
// initalizing the Registry with native key types and their managers
// that Tink supports out of the box.  These key types are divided in
// two groups:
//
//  - standard: secure and safe to use in new code. Over time, with
//    new developments in cryptanalysis and computing power, some
//    standard key types might become legacy.
//
//  - legacy: deprecated and insecure or obsolete, should not be used
//    in new code. Existing users should upgrade to one of the standard
//    key types.
//
// This divison allows for gradual retiring insecure or
// obsolete key types.
//
// For example, here is how one can obtain and use an HybridEncrypt primitive:
//
//   HybridEncryptFactory.RegisterStandardKeyTypes();
//   KeysetHandle keyset_handle = ...;
//   std::unique_ptr<HybridEncrypt> hybrid_encrypt = std::move(
//       HybridEncryptFactory.GetPrimitive(keyset_handle).ValueOrDie());
//   string plaintext = ...;
//   string context_info = ...;
//   string ciphertext =
//       hybrid_encrypt.Encrypt(plaintext, context_info).ValueOrDie();
//
class HybridEncryptFactory {
 public:
  // Registers standard HybridEncrypt key types and their managers
  // with the Registry.
  static util::Status RegisterStandardKeyTypes();

  // Registers legacy HybridEncrypt key types and their managers
  // with the Registry.
  static util::Status RegisterLegacyKeyTypes();

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
