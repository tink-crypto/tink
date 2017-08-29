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

#ifndef TINK_MAC_MAC_FACTORY_H_
#define TINK_MAC_MAC_FACTORY_H_

#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/mac.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// MacFactory allows for obtaining a Mac primitive from a KeysetHandle.
//
// MacFactory gets primitives from the Registry, which can be initialized
// via convenience methods from MacConfig-class. Here is an example
// how one can obtain and use a Mac primitive:
//
//   MacConfig.RegisterStandardKeyTypes();
//   KeysetHandle keyset_handle = ...;
//   std::unique_ptr<Mac> mac =
//       std::move(MacFactory.GetPrimitive(keyset_handle).ValueOrDie());
//   string data = ...;
//   string mac_value = mac.ComputeMac(data).ValueOrDie();
//
class MacFactory {
 public:
  // Returns a Mac-primitive that uses key material from the keyset
  // specified via 'keyset_handle'.
  static crypto::tink::util::StatusOr<std::unique_ptr<Mac>> GetPrimitive(
      const KeysetHandle& keyset_handle);

  // Returns a Mac-primitive that uses key material from the keyset
  // specified via 'keyset_handle' and is instantiated by the given
  // 'custom_key_manager' (instead of the key manager from the Registry).
  static crypto::tink::util::StatusOr<std::unique_ptr<Mac>> GetPrimitive(
      const KeysetHandle& keyset_handle,
      const KeyManager<Mac>* custom_key_manager);

 private:
  MacFactory() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_MAC_FACTORY_H_
