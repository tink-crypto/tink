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

#include <typeindex>
#include <typeinfo>
#include <unordered_map>

#include "absl/base/thread_annotations.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "tink/catalogue.h"
#include "tink/key_manager.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
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
      const std::string& catalogue_name) const LOCKS_EXCLUDED(maps_mutex_);

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
      const std::string& type_url) const LOCKS_EXCLUDED(maps_mutex_);


  template <class P>
  crypto::tink::util::Status RegisterPrimitiveWrapper(
      PrimitiveWrapper<P>* wrapper) LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data)
      const LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const std::string& type_url, const portable_proto::MessageLite& key)
      const LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(const google::crypto::tink::KeyTemplate& key_template)
      const LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(const std::string& type_url, const std::string& serialized_private_key)
      const LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> Wrap(
      std::unique_ptr<PrimitiveSet<P>> primitive_set) const
      LOCKS_EXCLUDED(maps_mutex_);

  void Reset() LOCKS_EXCLUDED(maps_mutex_);

 private:
  // All information for a given type url.
  struct KeyTypeInfo {
    KeyTypeInfo(std::shared_ptr<void> key_manager, std::type_index type_index,
                const char* type_id_name, bool new_key_allowed,
                const KeyFactory& key_factory)
        : key_manager(std::move(key_manager)),
          type_index(type_index),
          type_id_name(type_id_name),
          new_key_allowed(new_key_allowed),
          key_factory(key_factory) {}

    // A pointer to a KeyManager<P>. We use a shared_ptr because
    // shared_ptr<void> is valid (as opposed to unique_ptr<void>).
    const std::shared_ptr<void> key_manager;
    // std::type_index of the primitive for which this key was inserted.
    std::type_index type_index;
    // TypeId of the primitive for which this key was inserted.
    const std::string type_id_name;
    // Whether the key manager allows creating new keys.
    bool new_key_allowed;
    // The factory which can produce keys of this type.
    const KeyFactory& key_factory;
  };

  // All information for a given primitive label.
  struct LabelInfo {
    LabelInfo(std::shared_ptr<void> catalogue, std::type_index type_index,
              const char* type_id_name)
        : catalogue(std::move(catalogue)),
          type_index(type_index),
          type_id_name(type_id_name) {}
    // A pointer to the underlying Catalogue<P>. We use a shared_ptr because
    // shared_ptr<void> is valid (as opposed to unique_ptr<void>).
    const std::shared_ptr<void> catalogue;
    // std::type_index of the primitive for which this key was inserted.
    std::type_index type_index;
    // TypeId name of the primitive for which this key was inserted.
    const std::string type_id_name;
  };

  RegistryImpl() = default;
  RegistryImpl(const RegistryImpl&) = delete;
  RegistryImpl& operator=(const RegistryImpl&) = delete;

  template <class P>
  crypto::tink::util::StatusOr<const PrimitiveWrapper<P>*> get_wrapper()
      const LOCKS_EXCLUDED(maps_mutex_);


  mutable absl::Mutex maps_mutex_;
  std::unordered_map<std::string, KeyTypeInfo> type_url_to_info_
      GUARDED_BY(maps_mutex_);
  // A map from the type_id to the corresponding wrapper. We use a shared_ptr
  // because shared_ptr<void> is valid (as opposed to unique_ptr<void>).
  std::unordered_map<std::type_index, std::shared_ptr<void>>
      primitive_to_wrapper_ GUARDED_BY(maps_mutex_);

  std::unordered_map<std::string, LabelInfo> name_to_catalogue_map_
      GUARDED_BY(maps_mutex_);
};

template <class P>
crypto::tink::util::Status RegistryImpl::AddCatalogue(
    const std::string& catalogue_name, Catalogue<P>* catalogue) {
  if (catalogue == nullptr) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Parameter 'catalogue' must be non-null.");
  }
  std::shared_ptr<void> entry(catalogue);
  absl::MutexLock lock(&maps_mutex_);
  auto curr_catalogue = name_to_catalogue_map_.find(catalogue_name);
  if (curr_catalogue != name_to_catalogue_map_.end()) {
    auto existing =
        static_cast<Catalogue<P>*>(curr_catalogue->second.catalogue.get());
    if (std::type_index(typeid(*existing)) !=
        std::type_index(typeid(*catalogue))) {
      return ToStatusF(crypto::tink::util::error::ALREADY_EXISTS,
                       "A catalogue named '%s' has been already added.",
                       catalogue_name.c_str());
    }
  } else {
    name_to_catalogue_map_.emplace(
        std::piecewise_construct, std::forward_as_tuple(catalogue_name),
        std::forward_as_tuple(std::move(entry), std::type_index(typeid(P)),
                              typeid(P).name()));
  }
  return crypto::tink::util::Status::OK;
}

template <class P>
crypto::tink::util::StatusOr<const Catalogue<P>*> RegistryImpl::get_catalogue(
    const std::string& catalogue_name) const {
  absl::MutexLock lock(&maps_mutex_);
  auto catalogue_entry = name_to_catalogue_map_.find(catalogue_name);
  if (catalogue_entry == name_to_catalogue_map_.end()) {
    return ToStatusF(crypto::tink::util::error::NOT_FOUND,
                     "No catalogue named '%s' has been added.",
                     catalogue_name.c_str());
  }
  if (catalogue_entry->second.type_id_name != typeid(P).name()) {
    return ToStatusF(crypto::tink::util::error::INVALID_ARGUMENT,
                     "Wrong Primitive type for catalogue named '%s': "
                     "got '%s', expected '%s'",
                     catalogue_name.c_str(), typeid(P).name(),
                     catalogue_entry->second.type_id_name.c_str());
  }
  return static_cast<Catalogue<P>*>(catalogue_entry->second.catalogue.get());
}

template <class P>
crypto::tink::util::Status RegistryImpl::RegisterKeyManager(
    KeyManager<P>* manager, bool new_key_allowed) {
  if (manager == nullptr) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Parameter 'manager' must be non-null.");
  }
  std::shared_ptr<void> entry(manager);
  std::string type_url = manager->get_key_type();
  if (!manager->DoesSupport(type_url)) {
    return ToStatusF(crypto::tink::util::error::INVALID_ARGUMENT,
                     "The manager does not support type '%s'.",
                     type_url.c_str());
  }
  absl::MutexLock lock(&maps_mutex_);
  auto it = type_url_to_info_.find(type_url);
  if (it != type_url_to_info_.end()) {
    auto existing = static_cast<KeyManager<P>*>(it->second.key_manager.get());
    if (std::type_index(typeid(*existing)) !=
        std::type_index(typeid(*manager))) {
      return ToStatusF(crypto::tink::util::error::ALREADY_EXISTS,
                       "A manager for type '%s' has been already registered.",
                       type_url.c_str());
    } else {
      if (!it->second.new_key_allowed && new_key_allowed) {
        return ToStatusF(crypto::tink::util::error::ALREADY_EXISTS,
                         "A manager for type '%s' has been already registered "
                         "with forbidden new key operation.",
                         type_url.c_str());
      }
      it->second.new_key_allowed = new_key_allowed;
    }
  } else {
    type_url_to_info_.emplace(
        std::piecewise_construct, std::forward_as_tuple(type_url),
        std::forward_as_tuple(std::move(entry), std::type_index(typeid(P)),
                              typeid(P).name(), new_key_allowed,
                              manager->get_key_factory()));
  }
  return crypto::tink::util::Status::OK;
}

template <class P>
crypto::tink::util::Status RegistryImpl::RegisterPrimitiveWrapper(
    PrimitiveWrapper<P>* wrapper) {
  if (wrapper == nullptr) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Parameter 'wrapper' must be non-null.");
  }
  std::shared_ptr<void> entry(wrapper);

  absl::MutexLock lock(&maps_mutex_);
  auto it = primitive_to_wrapper_.find(std::type_index(typeid(P)));
  if (it != primitive_to_wrapper_.end()) {
    if (std::type_index(
            typeid(*static_cast<PrimitiveWrapper<P>*>(it->second.get()))) !=
        std::type_index(
            typeid(*static_cast<PrimitiveWrapper<P>*>(entry.get())))) {
      return ToStatusF(
          crypto::tink::util::error::ALREADY_EXISTS,
          "A wrapper named for this primitive has already been added.");
    }
    return crypto::tink::util::Status::OK;
  }
  primitive_to_wrapper_.insert(
      std::make_pair(std::type_index(typeid(P)), std::move(entry)));
  return crypto::tink::util::Status::OK;
}

template <class P>
crypto::tink::util::StatusOr<const KeyManager<P>*>
RegistryImpl::get_key_manager(const std::string& type_url) const {
  absl::MutexLock lock(&maps_mutex_);
  auto it = type_url_to_info_.find(type_url);
  if (it == type_url_to_info_.end()) {
    return ToStatusF(crypto::tink::util::error::NOT_FOUND,
                     "No manager for type '%s' has been registered.",
                     type_url.c_str());
  }
  if (it->second.type_index != std::type_index(typeid(P))) {
    return ToStatusF(crypto::tink::util::error::INVALID_ARGUMENT,
                     "Wrong Primitive type for key type '%s': "
                     "got '%s', expected '%s'",
                     type_url.c_str(), typeid(P).name(),
                     it->second.type_id_name.c_str());
  }
  return static_cast<KeyManager<P>*>(it->second.key_manager.get());
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::GetPrimitive(
    const google::crypto::tink::KeyData& key_data) const {
  auto key_manager_result = get_key_manager<P>(key_data.type_url());
  if (key_manager_result.ok()) {
    return key_manager_result.ValueOrDie()->GetPrimitive(key_data);
  }
  return key_manager_result.status();
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::GetPrimitive(
    const std::string& type_url, const portable_proto::MessageLite& key) const {
  auto key_manager_result = get_key_manager<P>(type_url);
  if (key_manager_result.ok()) {
    return key_manager_result.ValueOrDie()->GetPrimitive(key);
  }
  return key_manager_result.status();
}

template <class P>
crypto::tink::util::StatusOr<const PrimitiveWrapper<P>*>
RegistryImpl::get_wrapper() const {
  absl::MutexLock lock(&maps_mutex_);
  auto it = primitive_to_wrapper_.find(std::type_index(typeid(P)));
  if (it == primitive_to_wrapper_.end()) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrCat("No wrapper registered for type ", typeid(P).name()));
  }
  return static_cast<PrimitiveWrapper<P>*>(it->second.get());
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::Wrap(
    std::unique_ptr<PrimitiveSet<P>> primitive_set) const {
  if (primitive_set == nullptr) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Parameter 'primitive_set' must be non-null.");
  }
  util::StatusOr<const PrimitiveWrapper<P>*> wrapper_result = get_wrapper<P>();
  if (!wrapper_result.ok()) {
    return wrapper_result.status();
  }
  crypto::tink::util::StatusOr<std::unique_ptr<P>> primitive_result =
      wrapper_result.ValueOrDie()->Wrap(std::move(primitive_set));
  return std::move(primitive_result);
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_REGISTRY_IMPL_H_
