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

#include "tink/config/tink_config.h"

#include "tink/config.h"
#include "tink/key_manager.h"
#include "tink/registry.h"
#include "tink/daead/deterministic_aead_config.h"
#include "tink/hybrid/hybrid_config.h"
#include "tink/signature/signature_config.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

namespace {

google::crypto::tink::RegistryConfig* GenerateRegistryConfig() {
  google::crypto::tink::RegistryConfig* config =
      new google::crypto::tink::RegistryConfig();
  config->MergeFrom(HybridConfig::Latest());  // includes Mac & Aead
  config->MergeFrom(SignatureConfig::Latest());
  config->MergeFrom(DeterministicAeadConfig::Latest());
  config->set_config_name("TINK");
  return config;
}

}  // anonymous namespace

// static
const google::crypto::tink::RegistryConfig& TinkConfig::Latest() {
  static auto config = GenerateRegistryConfig();
  return *config;
}

// static
util::Status TinkConfig::Register() {
  auto status = HybridConfig::Register();  // includes Mac & Aead
  if (!status.ok()) return status;
  status = SignatureConfig::Register();
  if (!status.ok()) return status;
  return DeterministicAeadConfig::Register();
}

}  // namespace tink
}  // namespace crypto
