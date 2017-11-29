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

#include "cc/config/tink_config.h"

#include "cc/config.h"
#include "cc/key_manager.h"
#include "cc/registry.h"
#include "cc/hybrid/hybrid_encrypt_config.h"
#include "cc/hybrid/hybrid_decrypt_config.h"
#include "cc/signature/signature_config.h"
#include "cc/util/status.h"

namespace crypto {
namespace tink {

namespace {

google::crypto::tink::RegistryConfig* GenerateRegistryConfig() {
  google::crypto::tink::RegistryConfig* config =
      new google::crypto::tink::RegistryConfig();
  config->MergeFrom(HybridEncryptConfig::Tink_1_1_0());  // includes Mac & Aead
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      HybridDecryptConfig::kCatalogueName, HybridDecryptConfig::kPrimitiveName,
      "EciesAeadHkdfPrivateKey", 0, true));
  config->MergeFrom(SignatureConfig::Tink_1_1_0());
  config->set_config_name("TINK_1_1_0");
  return config;
}

}  // anonymous namespace

// static
const google::crypto::tink::RegistryConfig& TinkConfig::Tink_1_1_0() {
  static auto config = GenerateRegistryConfig();
  return *config;
}

// static
util::Status TinkConfig::Init() {
  auto status = HybridEncryptConfig::Init();  // includes Mac & Aead
  if (!status.ok()) return status;
  status = HybridDecryptConfig::Init();
  if (!status.ok()) return status;
  return SignatureConfig::Init();
}

}  // namespace tink
}  // namespace crypto
