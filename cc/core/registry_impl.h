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
#ifndef TINK_CORE_REGISTRY_IMPL_H_
#define TINK_CORE_REGISTRY_IMPL_H_

#include <mutex>  // NOLINT(build/c++11)
#include <typeinfo>
#include <unordered_map>

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "tink/catalogue.h"
#include "tink/core/registry_impl.h"
#include "tink/key_manager.h"
#include "tink/keyset_handle.h"
#include "tink/primitive_set.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/validation.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class RegistryImpl {
 public:
  static RegistryImpl& GlobalInstance() {
    static RegistryImpl* instance = new RegistryImpl();
    return *instance;
  }

  template <class P>
  crypto::tink::util::StatusOr<const Catalogue<P>*> get_catalogue(
      const std::string& catalogue_name) LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::Status AddCatalogue(const std::string& catalogue_name,
                                          Catalogue<P>* catalogue)
      LOCKS_EXCLUDED(maps_mutex_);

  // Registers the given 'manager' for the key type 'manager->get_key_type()'.
  // Takes ownership of 'manager', which must be non-nullptr.
  template <class P>
  crypto::tink::util::Status RegisterKeyManager(KeyManager<P>* manager,
                                                bool new_key_allowed)
      LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::Status RegisterKeyManager(KeyManager<P>* manager)
      LOCKS_EXCLUDED(maps_mutex_) {
    return RegisterKeyManager(manager, /* new_key_allowed= */ true);
  }

  template <class P>
  crypto::tink::util::StatusOr<const KeyManager<P>*> get_key_manager(
      const std::string& type_url) LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data)
      LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const std::string& type_url, const portable_proto::MessageLite& key)
      LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<PrimitiveSet<P>>> GetPrimitives(
      const KeysetHandle& keyset_handle, const KeyManager<P>* custom_manager)
      LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(const google::crypto::tink::KeyTemplate& key_template)
      LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(const std::string& type_url, const std::string& serialized_private_key)
      LOCKS_EXCLUDED(maps_mutex_);

  void Reset() LOCKS_EXCLUDED(maps_mutex_);

 private:
  typedef std::unordered_map<std::string, std::unique_ptr<void, void (*)(void*)>>
      LabelToObjectMap;
  typedef std::unordered_map<std::string, const char*> LabelToTypeNameMap;
  typedef std::unordered_map<std::string, bool> LabelToBoolMap;
  typedef std::unordered_map<std::string, const KeyFactory*> LabelToKeyFactoryMap;

  RegistryImpl() = default;
  RegistryImpl(const RegistryImpl&) = delete;
  RegistryImpl& operator=(const RegistryImpl&) = delete;

  absl::Mutex maps_mutex_;
  // Maps for key manager data.
  LabelToObjectMap type_to_manager_map_ GUARDED_BY(maps_mutex_);
  LabelToTypeNameMap type_to_primitive_map_ GUARDED_BY(maps_mutex_);
  LabelToBoolMap type_to_new_key_allowed_map_ GUARDED_BY(maps_mutex_);
  LabelToKeyFactoryMap type_to_key_factory_map_ GUARDED_BY(maps_mutex_);
  // Maps for catalogue-data.
  LabelToObjectMap name_to_catalogue_map_ GUARDED_BY(maps_mutex_);
  LabelToTypeNameMap name_to_primitive_map_ GUARDED_BY(maps_mutex_);

  crypto::tink::util::StatusOr<bool> get_new_key_allowed(const std::string& type_url)
      SHARED_LOCKS_REQUIRED(maps_mutex_);
  crypto::tink::util::StatusOr<const KeyFactory*> get_key_factory(
      const std::string& type_url) SHARED_LOCKS_REQUIRED(maps_mutex_);
};

template <class P>
void delete_manager(void* t) {
  delete static_cast<KeyManager<P>*>(t);
}

template <class P>
void delete_catalogue(void* t) {
  delete static_cast<Catalogue<P>*>(t);
}

template <class P>
crypto::tink::util::Status RegistryImpl::AddCatalogue(
    const std::string& catalogue_name, Catalogue<P>* catalogue) {
  if (catalogue == nullptr) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Parameter 'catalogue' must be non-null.");
  }
  std::unique_ptr<void, void (*)(void*)> entry(catalogue, delete_catalogue<P>);
  absl::MutexLock lock(&maps_mutex_);
  auto curr_catalogue = name_to_catalogue_map_.find(catalogue_name);
  if (curr_catalogue != name_to_catalogue_map_.end()) {
    auto existing = static_cast<Catalogue<P>*>(curr_catalogue->second.get());
    if (typeid(*existing).name() != typeid(*catalogue).name()) {
      return ToStatusF(crypto::tink::util::error::ALREADY_EXISTS,
                       "A catalogue named '%s' has been already added.",
                       catalogue_name.c_str());
    }
  } else {
    name_to_catalogue_map_.insert(
        std::make_pair(catalogue_name, std::move(entry)));
    name_to_primitive_map_.insert(
        std::make_pair(catalogue_name, typeid(P).name()));
  }
  return crypto::tink::util::Status::OK;
}

template <class P>
crypto::tink::util::StatusOr<const Catalogue<P>*> RegistryImpl::get_catalogue(
    const std::string& catalogue_name) {
  absl::MutexLock lock(&maps_mutex_);
  auto catalogue_entry = name_to_catalogue_map_.find(catalogue_name);
  if (catalogue_entry == name_to_catalogue_map_.end()) {
    return ToStatusF(crypto::tink::util::error::NOT_FOUND,
                     "No catalogue named '%s' has been added.",
                     catalogue_name.c_str());
  }
  if (name_to_primitive_map_[catalogue_name] != typeid(P).name()) {
    return ToStatusF(crypto::tink::util::error::INVALID_ARGUMENT,
                     "Wrong Primitive type for catalogue named '%s': "
                     "got '%s', expected '%s'",
                     catalogue_name.c_str(), typeid(P).name(),
                     name_to_primitive_map_[catalogue_name]);
  }
  return static_cast<Catalogue<P>*>(catalogue_entry->second.get());
}

template <class P>
crypto::tink::util::Status RegistryImpl::RegisterKeyManager(
    KeyManager<P>* manager, bool new_key_allowed) {
  if (manager == nullptr) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Parameter 'manager' must be non-null.");
  }
  std::string type_url = manager->get_key_type();
  std::unique_ptr<void, void (*)(void*)> entry(manager, delete_manager<P>);
  if (!manager->DoesSupport(type_url)) {
    return ToStatusF(crypto::tink::util::error::INVALID_ARGUMENT,
                     "The manager does not support type '%s'.",
                     type_url.c_str());
  }
  absl::MutexLock lock(&maps_mutex_);
  auto curr_manager = type_to_manager_map_.find(type_url);
  if (curr_manager != type_to_manager_map_.end()) {
    auto existing = static_cast<KeyManager<P>*>(curr_manager->second.get());
    if (typeid(*existing).name() != typeid(*manager).name()) {
      return ToStatusF(crypto::tink::util::error::ALREADY_EXISTS,
                       "A manager for type '%s' has been already registered.",
                       type_url.c_str());
    } else {
      auto curr_new_key_allowed = type_to_new_key_allowed_map_.find(type_url);
      if (!curr_new_key_allowed->second && new_key_allowed) {
        return ToStatusF(crypto::tink::util::error::ALREADY_EXISTS,
                         "A manager for type '%s' has been already registered "
                         "with forbidden new key operation.",
                         type_url.c_str());
      } else {
        curr_new_key_allowed->second = new_key_allowed;
      }
    }
  } else {
    type_to_manager_map_.insert(std::make_pair(type_url, std::move(entry)));
    type_to_primitive_map_.insert(std::make_pair(type_url, typeid(P).name()));
    type_to_new_key_allowed_map_.insert(
        std::make_pair(type_url, new_key_allowed));
    type_to_key_factory_map_.insert(
        std::make_pair(type_url, &(manager->get_key_factory())));
  }
  return crypto::tink::util::Status::OK;
}

template <class P>
crypto::tink::util::StatusOr<const KeyManager<P>*>
RegistryImpl::get_key_manager(const std::string& type_url) {
  absl::MutexLock lock(&maps_mutex_);
  auto manager_entry = type_to_manager_map_.find(type_url);
  if (manager_entry == type_to_manager_map_.end()) {
    return ToStatusF(crypto::tink::util::error::NOT_FOUND,
                     "No manager for type '%s' has been registered.",
                     type_url.c_str());
  }
  if (type_to_primitive_map_[type_url] != typeid(P).name()) {
    return ToStatusF(crypto::tink::util::error::INVALID_ARGUMENT,
                     "Wrong Primitive type for key type '%s': "
                     "got '%s', expected '%s'",
                     type_url.c_str(), typeid(P).name(),
                     type_to_primitive_map_[type_url]);
  }
  return static_cast<KeyManager<P>*>(manager_entry->second.get());
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::GetPrimitive(
    const google::crypto::tink::KeyData& key_data) {
  auto key_manager_result = get_key_manager<P>(key_data.type_url());
  if (key_manager_result.ok()) {
    return key_manager_result.ValueOrDie()->GetPrimitive(key_data);
  }
  return key_manager_result.status();
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::GetPrimitive(
    const std::string& type_url, const portable_proto::MessageLite& key) {
  auto key_manager_result = get_key_manager<P>(type_url);
  if (key_manager_result.ok()) {
    return key_manager_result.ValueOrDie()->GetPrimitive(key);
  }
  return key_manager_result.status();
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<PrimitiveSet<P>>>
RegistryImpl::GetPrimitives(const KeysetHandle& keyset_handle,
                            const KeyManager<P>* custom_manager) {
  crypto::tink::util::Status status =
      ValidateKeyset(keyset_handle.get_keyset());
  if (!status.ok()) return status;
  std::unique_ptr<PrimitiveSet<P>> primitives(new PrimitiveSet<P>());
  for (const google::crypto::tink::Keyset::Key& key :
       keyset_handle.get_keyset().key()) {
    if (key.status() == google::crypto::tink::KeyStatusType::ENABLED) {
      std::unique_ptr<P> primitive;
      if (custom_manager != nullptr &&
          custom_manager->DoesSupport(key.key_data().type_url())) {
        auto primitive_result = custom_manager->GetPrimitive(key.key_data());
        if (!primitive_result.ok()) return primitive_result.status();
        primitive = std::move(primitive_result.ValueOrDie());
      } else {
        auto primitive_result = GetPrimitive<P>(key.key_data());
        if (!primitive_result.ok()) return primitive_result.status();
        primitive = std::move(primitive_result.ValueOrDie());
      }
      auto entry_result = primitives->AddPrimitive(std::move(primitive), key);
      if (!entry_result.ok()) return entry_result.status();
      if (key.key_id() == keyset_handle.get_keyset().primary_key_id()) {
        primitives->set_primary(entry_result.ValueOrDie());
      }
    }
  }
  return std::move(primitives);
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_REGISTRY_IMPL_H_
