// Copyright 2023 Google LLC
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

#include "tink/mac/internal/key_gen_config_v0.h"

#include "absl/memory/memory.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key_gen_configuration.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status AddMacKeyGenV0(KeyGenConfiguration& config) {
  util::Status status = KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesCmacKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return KeyGenConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<HmacKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
