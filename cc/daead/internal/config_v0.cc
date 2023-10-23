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

#include "tink/daead/internal/config_v0.h"

#include "absl/memory/memory.h"
#include "tink/configuration.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/deterministic_aead_wrapper.h"
#include "tink/internal/configuration_impl.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status AddDeterministicAeadV0(Configuration& config) {
  util::Status status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<DeterministicAeadWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  return ConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<AesSivKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
