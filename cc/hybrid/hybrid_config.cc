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

#include "tink/hybrid/hybrid_config.h"

#include "absl/memory/memory.h"
#include "tink/aead/aead_config.h"
#include "tink/config.h"
#include "tink/hybrid/hybrid_decrypt_catalogue.h"
#include "tink/hybrid/hybrid_encrypt_catalogue.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

namespace {

google::crypto::tink::RegistryConfig* GenerateRegistryConfig() {
  google::crypto::tink::RegistryConfig* config =
      new google::crypto::tink::RegistryConfig();
  config->MergeFrom(AeadConfig::Latest());
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      HybridConfig::kHybridDecryptCatalogueName,
      HybridConfig::kHybridDecryptPrimitiveName,
      "EciesAeadHkdfPrivateKey", 0, true));
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      HybridConfig::kHybridEncryptCatalogueName,
      HybridConfig::kHybridEncryptPrimitiveName,
      "EciesAeadHkdfPublicKey", 0, true));
  config->set_config_name("TINK_HYBRID");
  return config;
}

}  // anonymous namespace

constexpr char HybridConfig::kHybridDecryptCatalogueName[];
constexpr char HybridConfig::kHybridDecryptPrimitiveName[];
constexpr char HybridConfig::kHybridEncryptCatalogueName[];
constexpr char HybridConfig::kHybridEncryptPrimitiveName[];

// static
const google::crypto::tink::RegistryConfig& HybridConfig::Latest() {
  static const auto config = GenerateRegistryConfig();
  return *config;
}

// static
util::Status HybridConfig::Register() {
  auto status = AeadConfig::Register();
  if (!status.ok()) return status;
  status = Registry::AddCatalogue(kHybridDecryptCatalogueName,
                                  absl::make_unique<HybridDecryptCatalogue>());
  if (!status.ok()) return status;
  status = Registry::AddCatalogue(kHybridEncryptCatalogueName,
                                  absl::make_unique<HybridEncryptCatalogue>());
  if (!status.ok()) return status;
  return Config::Register(Latest());
}

}  // namespace tink
}  // namespace crypto
