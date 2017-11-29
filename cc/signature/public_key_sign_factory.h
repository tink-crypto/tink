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

#ifndef TINK_SIGNATURE_PUBLIC_KEY_SIGN_FACTORY_H_
#define TINK_SIGNATURE_PUBLIC_KEY_SIGN_FACTORY_H_

#include "cc/public_key_sign.h"
#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// PublicKeySignFactory allows for obtaining an PublicKeySign primitive
// from a KeysetHandle.
//
// PublicKeySignFactory gets primitives from the Registry, which can
// be initialized via convenience methods from SignatureConfig-class.
// Here is an example how one can obtain and use a PublicKeySign primitive:
//
//   auto status = SignatureConfig::Init();
//   if (!status.ok()) { ... };
//   status = Config::Register(SignatureConfig::Tink_1_1_0());
//   if (!status.ok()) { ... };
//   KeysetHandle keyset_handle = ...;
//   std::unique_ptr<PublicKeySign> public_key_sign = std::move(
//           PublicKeySignFactory.GetPrimitive(keyset_handle).ValueOrDie());
//   std::string data = ...;
//   auto sign_result = public_key_sign.Sign(data);
//   if (!sign_result.ok()) {
//     // Signing failed.
//     // ...
//   }
//   std::string signature = sign_result.ValueOrDie();
//
class PublicKeySignFactory {
 public:
  // Returns a PublicKeySign-primitive that uses key material from the keyset
  // specified via 'keyset_handle'.
  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>>
      GetPrimitive(const KeysetHandle& keyset_handle);

  // Returns a PublicKeySign-primitive that uses key material from the keyset
  // specified via 'keyset_handle' and is instantiated by the given
  // 'custom_key_manager' (instead of the key manager from the Registry).
  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>>
      GetPrimitive(const KeysetHandle& keyset_handle,
                   const KeyManager<PublicKeySign>* custom_key_manager);

 private:
  PublicKeySignFactory() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_PUBLIC_KEY_SIGN_FACTORY_H_
