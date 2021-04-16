// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/streaming_aead_config.h"

#include "absl/memory/memory.h"
#include "tink/config/config_util.h"
#include "tink/config/tink_fips.h"
#include "tink/registry.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/streamingaead/streaming_aead_wrapper.h"
#include "tink/util/status.h"

using google::crypto::tink::RegistryConfig;

namespace crypto {
namespace tink {

// static
const RegistryConfig& StreamingAeadConfig::Latest() {
  static const RegistryConfig* config = new RegistryConfig();
  return *config;
}

// static
util::Status StreamingAeadConfig::Register() {
  // Register primitive wrapper.
  auto status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<StreamingAeadWrapper>());

  // Currently there are no streaming encryption key managers which only use
  // FIPS-validated implementations, therefore none will be registered in
  if (IsFipsModeEnabled()) {
    return util::OkStatus();
  }

  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesGcmHkdfStreamingKeyManager>(), true);
  if (!status.ok()) return status;

  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesCtrHmacStreamingKeyManager>(), true);
  if (!status.ok()) return status;

  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
