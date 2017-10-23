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

#ifndef TINK_CONFIG_H_
#define TINK_CONFIG_H_

#include "cc/aead.h"
#include "cc/catalogue.h"
#include "cc/config.h"
#include "cc/hybrid_encrypt.h"
#include "cc/hybrid_decrypt.h"
#include "cc/key_manager.h"
#include "cc/mac.h"
#include "cc/registry.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/strings.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

// Static methods for handling of Tink configurations.
//
// Configurations, i.e., collections of key types and their corresponding key
// managers supported by a specific run-time environment enable control
// of Tink setup via JSON-formatted config files that determine which key types
// are supported, and provide a mechanism for deprecation of obsolete/outdated
// cryptographic schemes (see tink/proto/config.proto for more info).
//
// Example usage:
//
// RegistryConfig registry_config = ...; // e.g. AeadConfig::Tink_1_1_0()
// Config::Register(registry_config);
//
class Config {
 public:
  // Returns a KeyTypeEntry for Tink key types with the specified parameters.
  static std::unique_ptr<google::crypto::tink::KeyTypeEntry>
  GetTinkKeyTypeEntry(
      const std::string& catalogue_name,
      const std::string& primitive_name,
      const std::string& key_proto_name,
      int key_manager_version,
      bool new_key_allowed);

  // Registers a key manager according to the specification in 'entry'.
  template <class P>
  static crypto::tink::util::Status Register(
      const google::crypto::tink::KeyTypeEntry& entry);

  // Registers key managers according to the specification in 'config'.
  static crypto::tink::util::Status Register(
      const google::crypto::tink::RegistryConfig& config);

 private:
  static crypto::tink::util::Status Validate(
      const google::crypto::tink::KeyTypeEntry& entry);
};

///////////////////////////////////////////////////////////////////////////////
// Implementation details of templated methods.


// static
template<class P>
crypto::tink::util::Status Config::Register(
    const google::crypto::tink::KeyTypeEntry& entry) {
  crypto::tink::util::Status status = Validate(entry);
  if (!status.ok()) return status;
  auto catalogue_result =
      Registry::get_catalogue<P>(entry.catalogue_name());
  if (!catalogue_result.ok()) return catalogue_result.status();
  auto catalogue = catalogue_result.ValueOrDie();
  auto key_manager_result = catalogue->GetKeyManager(
      entry.type_url(), entry.primitive_name(), entry.key_manager_version());
  if (!key_manager_result.ok()) return key_manager_result.status();
  return Registry::RegisterKeyManager<P>(
      entry.type_url(),
      key_manager_result.ValueOrDie().release(),
      entry.new_key_allowed());
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CONFIG_H_
