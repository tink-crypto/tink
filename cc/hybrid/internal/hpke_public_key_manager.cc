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

#include "tink/hybrid/internal/hpke_public_key_manager.h"

#include "tink/hybrid/internal/hpke_key_manager_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::HpkePublicKey;

util::Status HpkePublicKeyManager::ValidateKey(const HpkePublicKey& key) const {
  return ValidateKeyAndVersion(key, get_version());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
