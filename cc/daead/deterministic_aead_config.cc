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

#include "tink/daead/deterministic_aead_config.h"

#include "absl/memory/memory.h"
#include "tink/config/config_util.h"
#include "tink/config/tink_fips.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/deterministic_aead_wrapper.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

using google::crypto::tink::RegistryConfig;

namespace crypto {
namespace tink {

// static
const RegistryConfig& DeterministicAeadConfig::Latest() {
  static const RegistryConfig* config = new RegistryConfig();
  return *config;
}

// static
util::Status DeterministicAeadConfig::Register() {
  // Currently there are no FIPS-validated deterministic AEAD key managers
  // available, therefore none will be registered in FIPS only mode.
  if (IsFipsModeEnabled()) {
    return util::OkStatus();
  }

  // Register non-FIPS key managers.
  auto status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesSivKeyManager>(), true);
  if (!status.ok()) return status;

  // Register primitive wrapper.
  return Registry::RegisterPrimitiveWrapper(
      absl::make_unique<DeterministicAeadWrapper>());
}

}  // namespace tink
}  // namespace crypto
