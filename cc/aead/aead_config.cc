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

#include "cc/aead/aead_config.h"

#include "cc/config.h"
#include "cc/registry.h"
#include "cc/aead/aead_catalogue.h"
#include "cc/mac/mac_config.h"
#include "cc/util/status.h"
#include "proto/config.pb.h"

namespace util = crypto::tink::util;

using google::crypto::tink::RegistryConfig;

namespace crypto {
namespace tink {

namespace {

google::crypto::tink::RegistryConfig* GenerateRegistryConfig() {
  google::crypto::tink::RegistryConfig* config =
      new google::crypto::tink::RegistryConfig();
  config->MergeFrom(MacConfig::Tink_1_1_0());
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      AeadConfig::kCatalogueName, AeadConfig::kPrimitiveName,
      "AesCtrHmacAeadKey", 0, true));
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      AeadConfig::kCatalogueName, AeadConfig::kPrimitiveName,
      "AesGcmKey", 0, true));
  config->set_config_name("TINK_AEAD_1_1_0");
  return config;
}

}  // anonymous namespace

constexpr char AeadConfig::kCatalogueName[];
constexpr char AeadConfig::kPrimitiveName[];

// static
const google::crypto::tink::RegistryConfig& AeadConfig::Tink_1_1_0() {
  static const auto config = GenerateRegistryConfig();
  return *config;
}

// static
util::Status AeadConfig::RegisterStandardKeyTypes() {
  auto status = Init();
  if (!status.ok()) return status;
  return Config::Register(Tink_1_1_0());
}

// static
util::Status AeadConfig::Init() {
  auto status = MacConfig::Init();
  if (!status.ok()) return status;
  return Registry::AddCatalogue(kCatalogueName, new AeadCatalogue());
}

}  // namespace tink
}  // namespace crypto
