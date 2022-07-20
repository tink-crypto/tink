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

#include "tink/mac/mac_config.h"

#include "absl/memory/memory.h"
#include "tink/chunkedmac/internal/chunked_mac_wrapper.h"
#include "tink/config/config_util.h"
#include "tink/config/tink_fips.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/mac_wrapper.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

using google::crypto::tink::RegistryConfig;

namespace crypto {
namespace tink {

// static
const RegistryConfig& MacConfig::Latest() {
  static const RegistryConfig* config = new RegistryConfig();
  return *config;
}

// static
util::Status MacConfig::Register() {
  // Register primitive wrappers.
  auto status =
      Registry::RegisterPrimitiveWrapper(absl::make_unique<MacWrapper>());
  if (!status.ok()) return status;

  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<internal::ChunkedMacWrapper>());
  if (!status.ok()) return status;

  // Register key managers which utilize the FIPS validated BoringCrypto
  // implementations.
  status = Registry::RegisterKeyTypeManager(absl::make_unique<HmacKeyManager>(),
                                            true);
  if (!status.ok()) return status;

  if (IsFipsModeEnabled()) {
    return util::OkStatus();
  }

  // CMac in BoringSSL is not FIPS validated.
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesCmacKeyManager>(), true);
  if (!status.ok()) return status;

  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
