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

#include "cc/key_manager.h"
#include "cc/keyset_handle.h"
#include "cc/primitive_set.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/validation.h"
#include "google/protobuf/stubs/singleton.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/tink.pb.h"

namespace cloud {
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
  static Registry& get_default_registry();

  // Registers the given 'manager' for the key type identified by 'type_url'.
  // Takes ownership of 'manager', which must be non-nullptr.
  template <class P>
  util::Status RegisterKeyManager(const std::string& type_url,
                                  KeyManager<P>* manager);

  // Returns a key manager for the given type_url (if any found).
  // Keeps the ownership of the manager.
  // TODO(przydatek): consider changing return value to
  //   StatusOr<std::reference_wrapper<KeyManager<P>>>
  // (cannot return reference directly, as StatusOr does not support it,
  // see https://goo.gl/x0ymDz)
  template <class P>
  util::StatusOr<const KeyManager<P>*> get_key_manager(
      const std::string& type_url);

  // Convenience method for creating a new primitive for the key given
  // in 'key_data'.  It looks up a KeyManager identified by key_data.type_url,
  // and calls manager's GetPrimitive(key_data)-method.
  template <class P>
  util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const google::cloud::crypto::tink::KeyData& key_data);

  // Creates a set of primitives corresponding to the keys with
  // (status == ENABLED) in the keyset given in 'keyset_handle',
  // assuming all the corresponding key managers are present (keys
  // with (status != ENABLED) are skipped).
  //
  // The returned set is usually later "wrapped" into a class that
  // implements the corresponding Primitive-interface.
  template <class P>
  util::StatusOr<std::unique_ptr<PrimitiveSet<P>>> GetPrimitives(
      const KeysetHandle& keyset_handle, KeyManager<P>* custom_manager);

  Registry() {}

 private:
  static google::protobuf::internal::Singleton<Registry> default_registry_;
  typedef std::unordered_map<std::string, std::unique_ptr<void, void(*)(void*)>>
      TypeToManagerMap;
  typedef std::unordered_map<std::string, const char*>
      TypeToPrimitiveMap;

  std::mutex maps_mutex_;
  TypeToManagerMap type_to_manager_map_;       // guarded by maps_mutex_
  TypeToPrimitiveMap type_to_primitive_map_;   // guarded by maps_mutex_
};

///////////////////////////////////////////////////////////////////////////////
// Implementation details.

template <class P>
void delete_manager(void* t) {
  delete static_cast<KeyManager<P>*>(t);
}

// static
Registry& Registry::get_default_registry() {
  return *(default_registry_.get());
}

template <class P>
util::Status Registry::RegisterKeyManager(const std::string& type_url,
                                          KeyManager<P>* manager) {
  if (manager == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Parameter 'manager' must be non-null.");
  }
  std::unique_ptr<void, void(*)(void*)>
      entry(manager, delete_manager<P>);
  if (!manager->DoesSupport(type_url)) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "The manager does not support type '%s'.",
                     type_url.c_str());
  }
  std::lock_guard<std::mutex> lock(maps_mutex_);
  auto curr_manager = type_to_manager_map_.find(type_url);
  if (curr_manager != type_to_manager_map_.end()) {
    return ToStatusF(util::error::ALREADY_EXISTS,
                     "A manager for type '%s' has been already registered.",
                     type_url.c_str());
  }
  type_to_manager_map_.insert(
      std::make_pair(type_url, std::move(entry)));
  type_to_primitive_map_.insert(
      std::make_pair(type_url, typeid(P).name()));
  return util::Status::OK;
}

template <class P>
util::StatusOr<const KeyManager<P>*> Registry::get_key_manager(
    const std::string& type_url) {
  std::lock_guard<std::mutex> lock(maps_mutex_);
  auto manager_entry = type_to_manager_map_.find(type_url);
  if (manager_entry == type_to_manager_map_.end()) {
    return ToStatusF(util::error::NOT_FOUND,
                     "No manager for type '%s' has been registered.",
                     type_url.c_str());
  }
  if (type_to_primitive_map_[type_url] != typeid(P).name()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Wrong Primitive type for key type '%s': "
                     "got '%s', expected '%s'",
                     type_url.c_str(),
                     typeid(P).name(),
                     type_to_primitive_map_[type_url]);
  }
  return static_cast<KeyManager<P>*>(manager_entry->second.get());
}

template <class P>
util::StatusOr<std::unique_ptr<P>> Registry::GetPrimitive(
    const google::cloud::crypto::tink::KeyData& key_data) {
  auto key_manager_result = get_key_manager<P>(key_data.type_url());
  if (key_manager_result.ok()) {
    return key_manager_result.ValueOrDie()->GetPrimitive(key_data);
  }
  return key_manager_result.status();
}

template <class P>
util::StatusOr<std::unique_ptr<PrimitiveSet<P>>> Registry::GetPrimitives(
    const KeysetHandle& keyset_handle, KeyManager<P>* custom_manager) {
  util::Status status = ValidateKeyset(keyset_handle.get_keyset());
  if (!status.ok()) return status;
  std::unique_ptr<PrimitiveSet<P>> primitives(new PrimitiveSet<P>());
  for (const google::cloud::crypto::tink::Keyset::Key& key
           : keyset_handle.get_keyset().key()) {
    if (key.status() == google::cloud::crypto::tink::KeyStatusType::ENABLED) {
      std::unique_ptr<P> primitive;
      if (custom_manager != nullptr &&
          custom_manager->DoesSupport(key.key_data().type_url())) {
        auto primitive_result =
            custom_manager->GetPrimitive(key.key_data());
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
}  // namespace cloud

#endif  // TINK_REGISTRY_H_
