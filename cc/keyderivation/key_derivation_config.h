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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_KEYDERIVATION_KEY_DERIVATION_CONFIG_H_
#define TINK_KEYDERIVATION_KEY_DERIVATION_CONFIG_H_

#include "tink/util/status.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Static methods and constants for registering to the Registry all
// KeysetDeriver key types supported in a particular release of Tink.
//
// To register all KeysetDeriver key types, one can do:
//
//   crypto::tink::util::Status status = KeyDerivationConfig::Register();
//
class KeyDerivationConfig {
 public:
  // Registers KeysetDeriver primitive wrapper and key managers for all
  // KeyDerivation key types from the current Tink release.
  static crypto::tink::util::Status Register();

 private:
  KeyDerivationConfig() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_KEY_DERIVATION_CONFIG_H_
