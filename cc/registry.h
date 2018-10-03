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

#include <memory>
#include <string>

#include "tink/core/registry_impl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

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
      const std::string& catalogue_name) {
    return RegistryImpl::GlobalInstance().get_catalogue<P>(catalogue_name);
  }

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
  static crypto::tink::util::Status AddCatalogue(const std::string& catalogue_name,
                                                 Catalogue<P>* catalogue) {
    return RegistryImpl::GlobalInstance().AddCatalogue<P>(catalogue_name,
                                                          catalogue);
  }

  // Registers the given 'manager' for the key type 'manager->get_key_type()'.
  // Takes ownership of 'manager', which must be non-nullptr.
  template <class P>
  static crypto::tink::util::Status RegisterKeyManager(KeyManager<P>* manager,
                                                       bool new_key_allowed) {
    return RegistryImpl::GlobalInstance().RegisterKeyManager(manager,
                                                             new_key_allowed);
  }

  template <class P>
  static crypto::tink::util::Status RegisterKeyManager(KeyManager<P>* manager) {
    return RegistryImpl::GlobalInstance().RegisterKeyManager(manager);
  }

  // Returns a key manager for the given type_url (if any found).
  // Keeps the ownership of the manager.
  // TODO(przydatek): consider changing return value to
  //   StatusOr<std::reference_wrapper<KeyManager<P>>>
  // (cannot return reference directly, as StatusOr does not support it,
  // see https://goo.gl/x0ymDz)
  template <class P>
  static crypto::tink::util::StatusOr<const KeyManager<P>*> get_key_manager(
      const std::string& type_url) {
    return RegistryImpl::GlobalInstance().get_key_manager<P>(type_url);
  }

  // Convenience method for creating a new primitive for the key given
  // in 'key_data'.  It looks up a KeyManager identified by key_data.type_url,
  // and calls manager's GetPrimitive(key_data)-method.
  template <class P>
  static crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) {
    return RegistryImpl::GlobalInstance().GetPrimitive<P>(key_data);
  }
  // Convenience method for creating a new primitive for the key given
  // in 'key'.  It looks up a KeyManager identified by type_url,
  // and calls manager's GetPrimitive(key)-method.
  template <class P>
  static crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const std::string& type_url, const portable_proto::MessageLite& key) {
    return RegistryImpl::GlobalInstance().GetPrimitive<P>(type_url, key);
  }

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
                const KeyManager<P>* custom_manager) {
    return RegistryImpl::GlobalInstance().GetPrimitives<P>(keyset_handle,
                                                           custom_manager);
  }

  // Generates a new KeyData for the specified 'key_template'.
  // It looks up a KeyManager identified by key_template.type_url,
  // and calls KeyManager::NewKeyData.
  // This method should be used solely for key management.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(const google::crypto::tink::KeyTemplate& key_template) {
    return RegistryImpl::GlobalInstance().NewKeyData(key_template);
  }

  // Convenience method for extracting the public key data from the
  // private key given in serialized_private_key.
  // It looks up a KeyManager identified by type_url, whose KeyFactory must be
  // a PrivateKeyFactory, and calls PrivateKeyFactory::GetPublicKeyData.
  static crypto::tink::util::StatusOr<
      std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(const std::string& type_url,
                   const std::string& serialized_private_key) {
    return RegistryImpl::GlobalInstance().GetPublicKeyData(
        type_url, serialized_private_key);
  }

  // Resets the registry.
  // After reset the registry is empty, i.e. it contains neither catalogues
  // nor key managers. This method is intended for testing only.
  static void Reset() { return RegistryImpl::GlobalInstance().Reset(); }
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_REGISTRY_H_
