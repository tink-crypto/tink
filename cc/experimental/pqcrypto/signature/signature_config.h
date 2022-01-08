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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SIGNATURE_CONFIG_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SIGNATURE_CONFIG_H_

#include "tink/util/status.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Static methods for registering with the Registry
// all instances of experimental signature key types supported in a particular
// release of Tink, i.e. key types that correspond to primitives
// PublicKeySign and PublicKeyVerify.
//
// To register all experiemntal signature key types from the current Tink
// release one calls PqSignatureConfigRegister().
//

// Registers PublicKeySign and PublicKeyVerify primitive wrappers, and key
// managers for all experimental implementations of PublicKeySign and
// PublicKeyVerify from the current Tink release.
crypto::tink::util::Status PqSignatureConfigRegister();

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SIGNATURE_CONFIG_H_
