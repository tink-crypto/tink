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

#include "tink/signature/signature_config.h"

#include "absl/memory/memory.h"
#include "tink/config.h"
#include "tink/registry.h"
#include "tink/signature/public_key_sign_catalogue.h"
#include "tink/signature/public_key_verify_catalogue.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

namespace {

google::crypto::tink::RegistryConfig* GenerateRegistryConfig() {
  google::crypto::tink::RegistryConfig* config =
      new google::crypto::tink::RegistryConfig();
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      SignatureConfig::kPublicKeySignCatalogueName,
      SignatureConfig::kPublicKeySignPrimitiveName,
      "EcdsaPrivateKey", 0, true));
  config->add_entry()->MergeFrom(*Config::GetTinkKeyTypeEntry(
      SignatureConfig::kPublicKeyVerifyCatalogueName,
      SignatureConfig::kPublicKeyVerifyPrimitiveName,
      "EcdsaPublicKey", 0, true));
  config->set_config_name("TINK_SIGNATURE");
  return config;
}

}  // anonymous namespace

constexpr char SignatureConfig::kPublicKeySignCatalogueName[];
constexpr char SignatureConfig::kPublicKeyVerifyCatalogueName[];
constexpr char SignatureConfig::kPublicKeySignPrimitiveName[];
constexpr char SignatureConfig::kPublicKeyVerifyPrimitiveName[];

// static
const google::crypto::tink::RegistryConfig& SignatureConfig::Latest() {
  static const auto config = GenerateRegistryConfig();
  return *config;
}

// static
util::Status SignatureConfig::Register() {
  auto status = Registry::AddCatalogue(
      kPublicKeySignCatalogueName, absl::make_unique<PublicKeySignCatalogue>());
  if (!status.ok()) return status;
  status =
      Registry::AddCatalogue(kPublicKeyVerifyCatalogueName,
                             absl::make_unique<PublicKeyVerifyCatalogue>());
  if (!status.ok()) return status;
  return Config::Register(Latest());
}

}  // namespace tink
}  // namespace crypto
