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
#include "tink/config.h"
#include "tink/mac/mac_catalogue.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

namespace {

google::crypto::tink::RegistryConfig* GenerateRegistryConfig() {
  google::crypto::tink::RegistryConfig* config =
      new google::crypto::tink::RegistryConfig();
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      MacConfig::kCatalogueName, MacConfig::kPrimitiveName,
      "HmacKey", 0, true));
  config->set_config_name("TINK_MAC");
  return config;
}

}  // anonymous namespace

constexpr char MacConfig::kCatalogueName[];
constexpr char MacConfig::kPrimitiveName[];

// static
const google::crypto::tink::RegistryConfig& MacConfig::Latest() {
  static auto config = GenerateRegistryConfig();
  return *config;
}

// static
util::Status MacConfig::Register() {
  auto status =
      Registry::AddCatalogue(kCatalogueName, absl::make_unique<MacCatalogue>());
  if (!status.ok()) return status;
  return Config::Register(Latest());
}

}  // namespace tink
}  // namespace crypto
