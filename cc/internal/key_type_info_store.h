// Copyright 2018 Google LLC
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

#ifndef TINK_INTERNAL_KEY_TYPE_INFO_STORE_H_
#define TINK_INTERNAL_KEY_TYPE_INFO_STORE_H_

#include <atomic>
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <typeindex>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_join.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/private_key_manager_impl.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/internal/fips_utils.h"
#include "tink/key_manager.h"

namespace crypto {
namespace tink {
namespace internal {

// Stores information about key types constructed from their KeyTypeManager or
// KeyManager. This is used by the Configuration and Registry classes.
//
// Once inserted, Info objects must remain valid for the lifetime of the
// KeyTypeInfoStore object, and the Info object's pointer stability is required.
// Elements in Info, which include the KeyTypeManager or KeyManager, must not
// be replaced.
//
// Example:
//  KeyTypeInfoStore store;
//  crypto::tink::util::Status status =
//      store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(), true);
//  crypto::tink::util::StatusOr<KeyTypeInfoStore::Info*> info =
//      store.Get(AesGcmKeyManager().get_key_type());
class KeyTypeInfoStore {
 public:
  KeyTypeInfoStore() = default;

  // Movable, but not copyable.
  KeyTypeInfoStore(KeyTypeInfoStore&& other) = default;
  KeyTypeInfoStore& operator=(KeyTypeInfoStore&& other) = default;

  // Information about a key type constructed from its KeyTypeManager or
  // KeyManager.
  class Info {
   public:
    // Takes ownership of `manager`.
    template <typename KeyProto, typename KeyFormatProto,
              typename... Primitives>
    Info(KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>* manager,
         bool new_key_allowed)
        : key_manager_type_index_(std::type_index(typeid(*manager))),
          public_key_type_manager_type_index_(absl::nullopt),
          new_key_allowed_(new_key_allowed),
          key_type_manager_(absl::WrapUnique(manager)),
          internal_key_factory_(
              absl::make_unique<internal::KeyFactoryImpl<KeyTypeManager<
                  KeyProto, KeyFormatProto, List<Primitives...>>>>(manager)),
          key_factory_(internal_key_factory_.get()),
          key_deriver_(CreateDeriverFunctionFor(manager)) {
      // TODO(C++17): Replace with a fold expression.
      (void)std::initializer_list<int>{
          0, (primitive_to_manager_.emplace(
                  std::type_index(typeid(Primitives)),
                  internal::MakeKeyManager<Primitives>(manager)),
              0)...};
    }

    // Takes ownership of `private_manager`, but not of `public_manager`, which
    // must only be alive for the duration of the constructor.
    template <typename PrivateKeyProto, typename KeyFormatProto,
              typename PublicKeyProto, typename PublicPrimitivesList,
              typename... PrivatePrimitives>
    Info(PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                               List<PrivatePrimitives...>>* private_manager,
         KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
             public_manager,
         bool new_key_allowed)
        : key_manager_type_index_(std::type_index(typeid(*private_manager))),
          public_key_type_manager_type_index_(
              std::type_index(typeid(*public_manager))),
          new_key_allowed_(new_key_allowed),
          key_type_manager_(absl::WrapUnique(private_manager)),
          internal_key_factory_(
              absl::make_unique<internal::PrivateKeyFactoryImpl<
                  PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                  List<PrivatePrimitives...>, PublicPrimitivesList>>(
                  private_manager, public_manager)),
          key_factory_(internal_key_factory_.get()),
          key_deriver_(CreateDeriverFunctionFor(private_manager)) {
      // TODO(C++17): Replace with a fold expression.
      (void)std::initializer_list<int>{
          0, (primitive_to_manager_.emplace(
                  std::type_index(typeid(PrivatePrimitives)),
                  internal::MakePrivateKeyManager<PrivatePrimitives>(
                      private_manager, public_manager)),
              0)...};
    }

    // Takes ownership of `manager`. KeyManager is the legacy/internal version
    // of KeyTypeManager.
    template <typename P>
    Info(KeyManager<P>* manager, bool new_key_allowed)
        : key_manager_type_index_(std::type_index(typeid(*manager))),
          public_key_type_manager_type_index_(absl::nullopt),
          new_key_allowed_(new_key_allowed),
          key_type_manager_(nullptr),
          internal_key_factory_(nullptr),
          key_factory_(&manager->get_key_factory()) {
      primitive_to_manager_.emplace(std::type_index(typeid(P)),
                                    absl::WrapUnique(manager));
    }

    template <typename P>
    crypto::tink::util::StatusOr<const KeyManager<P>*> get_key_manager(
        absl::string_view requested_type_url) const {
      auto it = primitive_to_manager_.find(std::type_index(typeid(P)));
      if (it == primitive_to_manager_.end()) {
        return crypto::tink::util::Status(
            absl::StatusCode::kInvalidArgument,
            absl::StrCat(
                "Primitive type ", typeid(P).name(),
                " not among supported primitives ",
                absl::StrJoin(
                    primitive_to_manager_.begin(), primitive_to_manager_.end(),
                    ", ",
                    [](std::string* out,
                       const std::pair<const std::type_index,
                                       std::unique_ptr<KeyManagerBase>>& kv) {
                      absl::StrAppend(out, kv.first.name());
                    }),
                " for type URL ", requested_type_url));
      }
      return static_cast<const KeyManager<P>*>(it->second.get());
    }

    const std::type_index& key_manager_type_index() const {
      return key_manager_type_index_;
    }

    const absl::optional<std::type_index>& public_key_type_manager_type_index()
        const {
      return public_key_type_manager_type_index_;
    }

    bool new_key_allowed() const { return new_key_allowed_.load(); }

    void set_new_key_allowed(bool b) { new_key_allowed_.store(b); }

    const KeyFactory& key_factory() const { return *key_factory_; }

    const std::function<crypto::tink::util::StatusOr<
        google::crypto::tink::KeyData>(absl::string_view, InputStream*)>&
    key_deriver() const {
      return key_deriver_;
    }

   private:
    // Dynamic type_index of the KeyManager or KeyTypeManager for this key type.
    std::type_index key_manager_type_index_;
    // Dynamic type_index of the public KeyTypeManager for this key type when
    // inserted into the registry via RegisterAsymmetricKeyManagers. Otherwise,
    // nullopt.
    absl::optional<std::type_index> public_key_type_manager_type_index_;
    // Whether the key manager allows the creation of new keys.
    std::atomic<bool> new_key_allowed_;

    // Map from primitive type_index to KeyManager.
    absl::flat_hash_map<std::type_index, std::unique_ptr<KeyManagerBase>>
        primitive_to_manager_;
    // Key type manager. Equals nullptr if Info was constructed from a
    // KeyManager.
    const std::shared_ptr<void> key_type_manager_;

    // Key factory. Equals nullptr if Info was constructed from a KeyManager.
    std::unique_ptr<const KeyFactory> internal_key_factory_;
    // Unowned version of `internal_key_factory_` if Info was constructed from a
    // KeyTypeManager. Key factory belonging to the KeyManager if Info was
    // constructed from a KeyManager.
    const KeyFactory* key_factory_;

    // Derives a key if Info was constructed from a KeyTypeManager with a
    // non-void KeyFormat type. Else, this function is empty and casting to a
    // bool returns false.
    std::function<crypto::tink::util::StatusOr<google::crypto::tink::KeyData>(
        absl::string_view, InputStream*)>
        key_deriver_;
  };

  // Adds a crypto::tink::KeyTypeManager to KeyTypeInfoStore. `new_key_allowed`
  // indicates whether `manager` may create new keys.
  template <class KeyTypeManager>
  crypto::tink::util::Status AddKeyTypeManager(
      std::unique_ptr<KeyTypeManager> manager, bool new_key_allowed);

  // Adds a pair of crypto::tink::PrivateKeyTypeManager and
  // crypto::tink::KeyTypeManager to KeyTypeInfoStore. `new_key_allowed`
  // indicates whether `private_manager` may create new keys.
  template <class PrivateKeyTypeManager, class PublicKeyTypeManager>
  crypto::tink::util::Status AddAsymmetricKeyTypeManagers(
      std::unique_ptr<PrivateKeyTypeManager> private_manager,
      std::unique_ptr<PublicKeyTypeManager> public_manager,
      bool new_key_allowed);

  // Adds a crypto::tink::KeyManager to KeyTypeInfoStore. `new_key_allowed`
  // indicates whether `manager` may create new keys. KeyManager is the
  // legacy/internal version of KeyTypeManager.
  template <class P>
  crypto::tink::util::Status AddKeyManager(
      std::unique_ptr<KeyManager<P>> manager, bool new_key_allowed);

  // Gets Info associated with `type_url`, returning either a valid, non-null
  // Info or an error.
  crypto::tink::util::StatusOr<Info*> Get(absl::string_view type_url) const;

  bool IsEmpty() const { return type_url_to_info_.empty(); }

 private:
  // Whether a key manager with `type_url` and `key_manager_type_index` can be
  // inserted.
  crypto::tink::util::Status IsInsertable(
      absl::string_view type_url, const std::type_index& key_manager_type_index,
      bool new_key_allowed) const;

  void Add(std::string type_url, std::unique_ptr<Info> info,
           bool new_key_allowed) {
    auto it = type_url_to_info_.find(type_url);
    if (it != type_url_to_info_.end()) {
      it->second->set_new_key_allowed(new_key_allowed);
    } else {
      type_url_to_info_.insert({type_url, std::move(info)});
    }
  }

  // Map from the type_url to Info.
  // Elements in Info must not be replaced, and pointer stability is required
  // for `Get()`.
  absl::flat_hash_map<std::string, std::unique_ptr<Info>> type_url_to_info_;
};

template <class P>
crypto::tink::util::Status KeyTypeInfoStore::AddKeyManager(
    std::unique_ptr<KeyManager<P>> manager, bool new_key_allowed) {
  std::string type_url = manager->get_key_type();
  if (!manager->DoesSupport(type_url)) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "The manager does not support type '%s'.", type_url);
  }

  crypto::tink::util::Status status = IsInsertable(
      type_url, std::type_index(typeid(*manager)), new_key_allowed);
  if (!status.ok()) {
    return status;
  }

  auto info = absl::make_unique<Info>(manager.release(), new_key_allowed);
  Add(type_url, std::move(info), new_key_allowed);
  return crypto::tink::util::OkStatus();
}

template <class KeyTypeManager>
crypto::tink::util::Status KeyTypeInfoStore::AddKeyTypeManager(
    std::unique_ptr<KeyTypeManager> manager, bool new_key_allowed) {
  // Check FIPS status.
  internal::FipsCompatibility fips_compatible = manager->FipsStatus();
  auto fips_status = internal::ChecksFipsCompatibility(fips_compatible);
  if (!fips_status.ok()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Failed registering the key manager for ",
                     typeid(*manager).name(),
                     " as it is not FIPS compatible: ", fips_status.message()));
  }

  std::string type_url = manager->get_key_type();
  crypto::tink::util::Status status = IsInsertable(
      type_url, std::type_index(typeid(*manager)), new_key_allowed);
  if (!status.ok()) {
    return status;
  }

  auto info = absl::make_unique<Info>(manager.release(), new_key_allowed);
  Add(type_url, std::move(info), new_key_allowed);
  return crypto::tink::util::OkStatus();
}

template <class PrivateKeyTypeManager, class PublicKeyTypeManager>
crypto::tink::util::Status KeyTypeInfoStore::AddAsymmetricKeyTypeManagers(
    std::unique_ptr<PrivateKeyTypeManager> private_manager,
    std::unique_ptr<PublicKeyTypeManager> public_manager,
    bool new_key_allowed) {
  std::string private_type_url = private_manager->get_key_type();
  std::string public_type_url = public_manager->get_key_type();
  if (private_type_url == public_type_url) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        "Passed in key managers must have different get_key_type() results.");
  }

  // Check FIPS status.
  auto private_fips_status =
      internal::ChecksFipsCompatibility(private_manager->FipsStatus());
  if (!private_fips_status.ok()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "Failed registering the key manager for ",
            typeid(*private_manager).name(),
            " as it is not FIPS compatible: ", private_fips_status.message()));
  }
  auto public_fips_status =
      internal::ChecksFipsCompatibility(public_manager->FipsStatus());
  if (!public_fips_status.ok()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "Failed registering the key manager for ",
            typeid(*public_manager).name(),
            " as it is not FIPS compatible: ", public_fips_status.message()));
  }

  crypto::tink::util::Status private_status =
      IsInsertable(private_type_url, std::type_index(typeid(*private_manager)),
                   new_key_allowed);
  if (!private_status.ok()) {
    return private_status;
  }
  crypto::tink::util::Status public_status =
      IsInsertable(public_type_url, std::type_index(typeid(*public_manager)),
                   new_key_allowed);
  if (!public_status.ok()) {
    return public_status;
  }

  util::StatusOr<KeyTypeInfoStore::Info*> private_found = Get(private_type_url);
  util::StatusOr<const KeyTypeInfoStore::Info*> public_found =
      Get(public_type_url);

  // Only one of the private and public key type managers is found.
  if (private_found.ok() && !public_found.ok()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(
            "Private key manager corresponding to ",
            typeid(*private_manager).name(),
            " was previously registered, but key manager corresponding to ",
            typeid(*public_manager).name(),
            " was not, so it's impossible to register them jointly"));
  }
  if (!private_found.ok() && public_found.ok()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Key manager corresponding to ",
                     typeid(*public_manager).name(),
                     " was previously registered, but private key manager "
                     "corresponding to ",
                     typeid(*private_manager).name(),
                     " was not, so it's impossible to register them jointly"));
  }

  // Both private and public key type managers are found.
  if (private_found.ok() && public_found.ok()) {
    if (!(*private_found)->public_key_type_manager_type_index().has_value()) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("private key manager corresponding to ",
                       typeid(*private_manager).name(),
                       " is already registered without public key manager, "
                       "cannot be re-registered with public key manager. "));
    }
    if ((*private_found)->public_key_type_manager_type_index() !=
        std::type_index(typeid(*public_manager))) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat(
              "private key manager corresponding to ",
              typeid(*private_manager).name(), " is already registered with ",
              (*private_found)->public_key_type_manager_type_index()->name(),
              ", cannot be re-registered with ",
              typeid(*public_manager).name()));
    }
    // Since `private_manager` passed the `IsInsertable` check above, the
    // `set_new_key_allowed` operation is permissible.
    (*private_found)->set_new_key_allowed(new_key_allowed);
    return crypto::tink::util::OkStatus();
  }

  // Both private and public key type managers were not found.
  auto private_info = absl::make_unique<Info>(
      private_manager.release(), public_manager.get(), new_key_allowed);
  Add(private_type_url, std::move(private_info), new_key_allowed);
  // TODO(b/265705174): Store public key type managers in an asymmetric pair
  // with new_key_allowed = false.
  auto public_info =
      absl::make_unique<Info>(public_manager.release(), new_key_allowed);
  Add(public_type_url, std::move(public_info), new_key_allowed);

  return crypto::tink::util::OkStatus();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_TYPE_INFO_STORE_H_
