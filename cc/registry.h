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

#ifndef TINK_REGISTRY_H_
#define TINK_REGISTRY_H_

#include <mutex>  // NOLINT(build/c++11)
#include <typeinfo>
#include <unordered_map>

#include "cc/catalogue.h"
#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/primitive_set.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/validation.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Registry for KeyMangers.
//
// It is essentially a big container (map) that for each supported key
// type holds a corresponding KeyManager object, which "understands"
// the key type (i.e. the KeyManager can instantiate the primitive
// corresponding to given key, or can generate new keys of the
// supported key type).  Registry is initialized at startup, and is
// later used to instantiate primitives for given keys or keysets.
// Keeping KeyManagers for all primitives in a single Registry (rather
// than having a separate KeyManager per primitive) enables modular
// construction of compound primitives from "simple" ones, e.g.,
// AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC.
//
// Note that regular users will usually not work directly with
// Registry, but rather via primitive factories, which in the
// background query the Registry for specific KeyManagers.  Registry
// is public though, to enable configurations with custom primitives
// and KeyManagers.
class Registry {
 public:
  // Returns a catalogue with the given name (if any found).
  // Keeps the ownership of the catalogue.
  // TODO(przydatek): consider changing return value to
  //   StatusOr<std::reference_wrapper<KeyManager<P>>>
  // (cannot return reference directly, as StatusOr does not support it,
  // see https://goo.gl/x0ymDz)
  template <class P>
  static crypto::tink::util::StatusOr<const Catalogue<P>*> get_catalogue(
      const std::string& catalogue_name);

  // Adds the given 'catalogue' under the specified 'catalogue_name',
  // to enable custom configuration of key types and key managers.
  //
  // Adding a custom catalogue should be a one-time operation,
  // and fails if the given 'catalogue' tries to override
  // an existing, different catalogue for the specified name.
  //
  // Takes ownership of 'catalogue', which must be non-nullptr
  // (in case of failure, 'catalogue' is deleted).
  template <class P>
  static crypto::tink::util::Status AddCatalogue(
      const std::string& catalogue_name, Catalogue<P>* catalogue);

  // Registers the given 'manager' for the key type identified by 'type_url'.
  // Takes ownership of 'manager', which must be non-nullptr.
  template <class P>
  static crypto::tink::util::Status RegisterKeyManager(
      const std::string& type_url, KeyManager<P>* manager,
      bool new_key_allowed);

  template <class P>
  static crypto::tink::util::Status RegisterKeyManager(
      const std::string& type_url, KeyManager<P>* manager) {
    return RegisterKeyManager(type_url, manager, /* new_key_allowed= */ true);
  }

  // Returns a key manager for the given type_url (if any found).
  // Keeps the ownership of the manager.
  // TODO(przydatek): consider changing return value to
  //   StatusOr<std::reference_wrapper<KeyManager<P>>>
  // (cannot return reference directly, as StatusOr does not support it,
  // see https://goo.gl/x0ymDz)
  template <class P>
  static crypto::tink::util::StatusOr<const KeyManager<P>*> get_key_manager(
      const std::string& type_url);

  // Convenience method for creating a new primitive for the key given
  // in 'key_data'.  It looks up a KeyManager identified by key_data.type_url,
  // and calls manager's GetPrimitive(key_data)-method.
  template <class P>
  static crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data);

  // Convenience method for creating a new primitive for the key given
  // in 'key'.  It looks up a KeyManager identified by type_url,
  // and calls manager's GetPrimitive(key)-method.
  template <class P>
  static crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const std::string& type_url, const google::protobuf::Message& key);

  // Creates a set of primitives corresponding to the keys with
  // (status == ENABLED) in the keyset given in 'keyset_handle',
  // assuming all the corresponding key managers are present (keys
  // with (status != ENABLED) are skipped).
  //
  // The returned set is usually later "wrapped" into a class that
  // implements the corresponding Primitive-interface.
  template <class P>
  static crypto::tink::util::StatusOr<std::unique_ptr<PrimitiveSet<P>>>
  GetPrimitives(const KeysetHandle& keyset_handle,
                const KeyManager<P>* custom_manager);

  // Resets the registry.
  // After reset the registry is empty, i.e. it contains neither catalogues
  // nor key managers. This method is intended for testing only.
  static void Reset();

 private:
  typedef std::unordered_map<std::string,
                             std::unique_ptr<void, void (*)(void*)>>
      LabelToObjectMap;
  typedef std::unordered_map<std::string, const char*> LabelToTypeNameMap;

  static std::mutex maps_mutex_;
  static LabelToObjectMap type_to_manager_map_;      // guarded by maps_mutex_
  static LabelToTypeNameMap type_to_primitive_map_;  // guarded by maps_mutex_
  static LabelToObjectMap name_to_catalogue_map_;    // guarded by maps_mutex_
  static LabelToTypeNameMap name_to_primitive_map_;  // guarded by maps_mutex_
};

///////////////////////////////////////////////////////////////////////////////
// Implementation details.

template <class P>
void delete_manager(void* t) {
  delete static_cast<KeyManager<P>*>(t);
}

template <class P>
void delete_catalogue(void* t) {
  delete static_cast<Catalogue<P>*>(t);
}

// static
template <class P>
crypto::tink::util::Status Registry::AddCatalogue(
    const std::string& catalogue_name, Catalogue<P>* catalogue) {
  if (catalogue == nullptr) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Parameter 'catalogue' must be non-null.");
  }
  std::unique_ptr<void, void (*)(void*)> entry(catalogue, delete_catalogue<P>);
  std::lock_guard<std::mutex> lock(maps_mutex_);
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

// static
template <class P>
crypto::tink::util::StatusOr<const Catalogue<P>*> Registry::get_catalogue(
    const std::string& catalogue_name) {
  std::lock_guard<std::mutex> lock(maps_mutex_);
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

// static
template <class P>
crypto::tink::util::Status Registry::RegisterKeyManager(
    const std::string& type_url, KeyManager<P>* manager, bool new_key_allowed) {
  if (manager == nullptr) {
    return crypto::tink::util::Status(
        crypto::tink::util::error::INVALID_ARGUMENT,
        "Parameter 'manager' must be non-null.");
  }
  std::unique_ptr<void, void (*)(void*)> entry(manager, delete_manager<P>);
  if (!manager->DoesSupport(type_url)) {
    return ToStatusF(crypto::tink::util::error::INVALID_ARGUMENT,
                     "The manager does not support type '%s'.",
                     type_url.c_str());
  }
  std::lock_guard<std::mutex> lock(maps_mutex_);
  auto curr_manager = type_to_manager_map_.find(type_url);
  if (curr_manager != type_to_manager_map_.end()) {
    auto existing = static_cast<KeyManager<P>*>(curr_manager->second.get());
    if (typeid(*existing).name() != typeid(*manager).name()) {
      return ToStatusF(crypto::tink::util::error::ALREADY_EXISTS,
                       "A manager for type '%s' has been already registered.",
                       type_url.c_str());
    }
  } else {
    type_to_manager_map_.insert(std::make_pair(type_url, std::move(entry)));
    type_to_primitive_map_.insert(std::make_pair(type_url, typeid(P).name()));
  }
  return crypto::tink::util::Status::OK;
}

// static
template <class P>
crypto::tink::util::StatusOr<const KeyManager<P>*> Registry::get_key_manager(
    const std::string& type_url) {
  std::lock_guard<std::mutex> lock(maps_mutex_);
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

// static
template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> Registry::GetPrimitive(
    const google::crypto::tink::KeyData& key_data) {
  auto key_manager_result = get_key_manager<P>(key_data.type_url());
  if (key_manager_result.ok()) {
    return key_manager_result.ValueOrDie()->GetPrimitive(key_data);
  }
  return key_manager_result.status();
}

// static
template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> Registry::GetPrimitive(
    const std::string& type_url, const google::protobuf::Message& key) {
  auto key_manager_result = get_key_manager<P>(type_url);
  if (key_manager_result.ok()) {
    return key_manager_result.ValueOrDie()->GetPrimitive(key);
  }
  return key_manager_result.status();
}

// static
template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<PrimitiveSet<P>>>
Registry::GetPrimitives(const KeysetHandle& keyset_handle,
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

#endif  // TINK_REGISTRY_H_
