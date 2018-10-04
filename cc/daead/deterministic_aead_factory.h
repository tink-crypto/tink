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

#ifndef TINK_DAEAD_DETERMINISTIC_AEAD_FACTORY_H_
#define TINK_DAEAD_DETERMINISTIC_AEAD_FACTORY_H_

#include "tink/deterministic_aead.h"
#include "tink/key_manager.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// DeterministicAeadFactory allows for obtaining an DeterministicAead primitive
// from a KeysetHandle.
//
// DeterministicAeadFactory gets primitives from the Registry, which can be
// initialized via a convenience method from DeterministicAeadConfig-class.
// Here is an example how one can obtain and use a DeterministicAead primitive:
//
//   auto status = DeterministicAeadConfig::Register();
//   if (!status.ok()) { /* fail with error */ }
//   KeysetHandle keyset_handle = ...;
//   std::unique_ptr<DeterministicAead> daead = std::move(
//       DeterministicAeadFactory::GetPrimitive(keyset_handle).ValueOrDie());
//   std::string plaintext = ...;
//   std::string aad = ...;
//   std::string ciphertext =
//       daead.DeterministicallyEncrypt(plaintext, aad).ValueOrDie();
//
class DeterministicAeadFactory {
 public:
  // Returns an DeterministicAead-primitive that uses key material from
  // the keyset specified via 'keyset_handle'.
  static crypto::tink::util::StatusOr<std::unique_ptr<DeterministicAead>>
  GetPrimitive(const KeysetHandle& keyset_handle);

  // Returns an DeterministicAead-primitive that uses key material from
  // the keyset specified via 'keyset_handle' and is instantiated by the given
  // 'custom_key_manager' (instead of the key manager from the Registry).
  static crypto::tink::util::StatusOr<std::unique_ptr<DeterministicAead>>
  GetPrimitive(const KeysetHandle& keyset_handle,
               const KeyManager<DeterministicAead>* custom_key_manager);

 private:
  DeterministicAeadFactory() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_DETERMINISTIC_AEAD_FACTORY_H_
