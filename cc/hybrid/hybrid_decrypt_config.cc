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

#include "cc/hybrid/hybrid_decrypt_config.h"

#include "cc/config.h"
#include "cc/aead/aead_config.h"
#include "cc/hybrid/hybrid_decrypt_catalogue.h"
#include "cc/util/status.h"
#include "proto/config.pb.h"

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

namespace {

google::crypto::tink::RegistryConfig* GenerateRegistryConfig() {
  google::crypto::tink::RegistryConfig* config =
      new google::crypto::tink::RegistryConfig();
  config->MergeFrom(AeadConfig::Tink_1_1_0());
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      HybridDecryptConfig::kCatalogueName, HybridDecryptConfig::kPrimitiveName,
      "EciesAeadHkdfPrivateKey", 0, true));
  config->set_config_name("TINK_HYBRID_DECRYPT_1_1_0");
  return config;
}

}  // anonymous namespace

constexpr char HybridDecryptConfig::kCatalogueName[];
constexpr char HybridDecryptConfig::kPrimitiveName[];

// static
const google::crypto::tink::RegistryConfig& HybridDecryptConfig::Tink_1_1_0() {
  static const auto config = GenerateRegistryConfig();
  return *config;
}

// static
util::Status HybridDecryptConfig::RegisterStandardKeyTypes() {
  auto status = Init();
  if (!status.ok()) return status;
  return Config::Register(Tink_1_1_0());
}

// static
util::Status HybridDecryptConfig::Init() {
  AeadConfig::Init();
  return Registry::AddCatalogue(kCatalogueName, new HybridDecryptCatalogue());
}

}  // namespace tink
}  // namespace crypto
