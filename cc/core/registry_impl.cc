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
#include "tink/core/registry_impl.h"

#include <mutex>  // NOLINT(build/c++11)

#include "tink/util/errors.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using crypto::tink::util::StatusOr;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;

namespace crypto {
namespace tink {

StatusOr<bool> RegistryImpl::get_new_key_allowed(const std::string& type_url) {
  auto new_key_entry = type_to_new_key_allowed_map_.find(type_url);
  if (new_key_entry == type_to_new_key_allowed_map_.end()) {
    return ToStatusF(util::error::NOT_FOUND,
                     "No manager for type '%s' has been registered.",
                     type_url.c_str());
  }
  return new_key_entry->second;
}

StatusOr<const KeyFactory*> RegistryImpl::get_key_factory(
    const std::string& type_url) {
  auto key_factory_entry = type_to_key_factory_map_.find(type_url);
  if (key_factory_entry == type_to_key_factory_map_.end()) {
    return ToStatusF(util::error::INTERNAL,
                     "No KeyFactory for key manager for type '%s' found.",
                     type_url.c_str());
  }
  return key_factory_entry->second;
}

StatusOr<std::unique_ptr<KeyData>> RegistryImpl::NewKeyData(
    const KeyTemplate& key_template) {
  absl::MutexLock lock(&maps_mutex_);

  auto new_key_allowed_result = get_new_key_allowed(key_template.type_url());
  if (!new_key_allowed_result.ok()) {
    return new_key_allowed_result.status();
  }
  if (!new_key_allowed_result.ValueOrDie()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "KeyManager for type '%s' does not allow "
                     "for creation of new keys.",
                     key_template.type_url().c_str());
  }
  auto key_factory_result = get_key_factory(key_template.type_url());
  if (!key_factory_result.ok()) {
    return key_factory_result.status();
  }
  auto factory = key_factory_result.ValueOrDie();
  auto result = factory->NewKeyData(key_template.value());
  return result;
}

StatusOr<std::unique_ptr<KeyData>> RegistryImpl::GetPublicKeyData(
    const std::string& type_url, const std::string& serialized_private_key) {
  absl::MutexLock lock(&maps_mutex_);
  auto key_factory_result = get_key_factory(type_url);
  if (!key_factory_result.ok()) {
    return key_factory_result.status();
  }
  auto factory =
      dynamic_cast<const PrivateKeyFactory*>(key_factory_result.ValueOrDie());
  if (factory == nullptr) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "KeyManager for type '%s' does not have "
                     "a PrivateKeyFactory.", type_url.c_str());
  }
  auto result = factory->GetPublicKeyData(serialized_private_key);
  return result;
}

void RegistryImpl::Reset() {
  absl::MutexLock lock(&maps_mutex_);
  type_to_manager_map_.clear();
  type_to_primitive_map_.clear();
  type_to_new_key_allowed_map_.clear();
  type_to_key_factory_map_.clear();
  name_to_catalogue_map_.clear();
  name_to_primitive_map_.clear();
}

}  // namespace tink
}  // namespace crypto
