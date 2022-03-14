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
#ifndef TINK_INTERNAL_REGISTRY_IMPL_H_
#define TINK_INTERNAL_REGISTRY_IMPL_H_

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <tuple>
#include <typeindex>
#include <typeinfo>
#include <utility>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/catalogue.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/private_key_manager_impl.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/keyset_wrapper.h"
#include "tink/internal/keyset_wrapper_impl.h"
#include "tink/key_manager.h"
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/validation.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class RegistryImpl {
 public:
  static RegistryImpl& GlobalInstance() {
    static RegistryImpl* instance = new RegistryImpl();
    return *instance;
  }

  RegistryImpl() = default;
  RegistryImpl(const RegistryImpl&) = delete;
  RegistryImpl& operator=(const RegistryImpl&) = delete;

  template <class P>
  crypto::tink::util::StatusOr<const Catalogue<P>*> get_catalogue(
      absl::string_view catalogue_name) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::Status AddCatalogue(absl::string_view catalogue_name,
                                          Catalogue<P>* catalogue)
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Registers the given 'manager' for the key type 'manager->get_key_type()'.
  // Takes ownership of 'manager', which must be non-nullptr.
  template <class P>
  crypto::tink::util::Status RegisterKeyManager(KeyManager<P>* manager,
                                                bool new_key_allowed = true)
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Takes ownership of 'manager', which must be non-nullptr.
  template <class KeyProto, class KeyFormatProto, class PrimitiveList>
  crypto::tink::util::Status RegisterKeyTypeManager(
      std::unique_ptr<KeyTypeManager<KeyProto, KeyFormatProto, PrimitiveList>>
          manager,
      bool new_key_allowed) ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Takes ownership of 'private_key_manager' and 'public_key_manager'. Both
  // must be non-nullptr.
  template <class PrivateKeyProto, class KeyFormatProto, class PublicKeyProto,
            class PrivatePrimitivesList, class PublicPrimitivesList>
  crypto::tink::util::Status RegisterAsymmetricKeyManagers(
      PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                            PrivatePrimitivesList>* private_key_manager,
      KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
          public_key_manager,
      bool new_key_allowed) ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<const KeyManager<P>*> get_key_manager(
      absl::string_view type_url) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Takes ownership of 'wrapper', which must be non-nullptr.
  template <class P, class Q>
  crypto::tink::util::Status RegisterPrimitiveWrapper(
      PrimitiveWrapper<P, Q>* wrapper) ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      absl::string_view type_url, const portable_proto::MessageLite& key) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(const google::crypto::tink::KeyTemplate& key_template) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(absl::string_view type_url,
                   absl::string_view serialized_private_key) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> Wrap(
      std::unique_ptr<PrimitiveSet<P>> primitive_set) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> WrapKeyset(
      const google::crypto::tink::Keyset& keyset) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::StatusOr<google::crypto::tink::KeyData> DeriveKey(
      const google::crypto::tink::KeyTemplate& key_template,
      InputStream* randomness) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  void Reset() ABSL_LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::Status RestrictToFipsIfEmpty() const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Registers a `monitoring_factory`. Only one factory can be registered,
  // subsequent calls to this method will return a kAlreadyExists error.
  crypto::tink::util::Status RegisterMonitoringClientFactory(
      std::unique_ptr<crypto::tink::MonitoringClientFactory> monitoring_factory)
      ABSL_LOCKS_EXCLUDED(monitoring_factory_mutex_);

  // Returns a pointer to the registered monitoring factory if any, and nullptr
  // otherwise.
  crypto::tink::MonitoringClientFactory* GetMonitoringClientFactory() const
      ABSL_LOCKS_EXCLUDED(monitoring_factory_mutex_) {
    absl::MutexLock lock(&monitoring_factory_mutex_);
    return monitoring_factory_.get();
  }

 private:
  // All information for a given type url.
  class KeyTypeInfo {
   public:
    // Takes ownership of the 'key_manager'.
    template <typename P>
    KeyTypeInfo(KeyManager<P>* key_manager, bool new_key_allowed)
        : key_manager_type_index_(std::type_index(typeid(*key_manager))),
          public_key_manager_type_index_(absl::nullopt),
          new_key_allowed_(new_key_allowed),
          internal_key_factory_(nullptr),
          key_factory_(&key_manager->get_key_factory()),
          key_type_manager_(nullptr) {
      primitive_to_manager_.emplace(std::type_index(typeid(P)),
                                    absl::WrapUnique(key_manager));
    }

    // Takes ownership of the 'key_manager'.
    template <typename KeyProto, typename KeyFormatProto,
              typename... Primitives>
    KeyTypeInfo(KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>*
                    key_manager,
                bool new_key_allowed)
        : key_manager_type_index_(std::type_index(typeid(*key_manager))),
          public_key_manager_type_index_(absl::nullopt),
          new_key_allowed_(new_key_allowed),
          internal_key_factory_(
              absl::make_unique<internal::KeyFactoryImpl<KeyTypeManager<
                  KeyProto, KeyFormatProto, List<Primitives...>>>>(
                  key_manager)),
          key_factory_(internal_key_factory_.get()),
          key_deriver_(CreateDeriverFunctionFor(key_manager)),
          key_type_manager_(absl::WrapUnique(key_manager)) {
      // TODO(C++17) replace with a fold expression
      (void)std::initializer_list<int>{
          0, (primitive_to_manager_.emplace(
                  std::type_index(typeid(Primitives)),
                  internal::MakeKeyManager<Primitives>(key_manager)),
              0)...};
    }

    // Takes ownership of the 'private_key_manager', but *not* of the
    // 'public_key_manager'. The public_key_manager must only be alive for the
    // duration of the constructor.
    template <typename PrivateKeyProto, typename KeyFormatProto,
              typename PublicKeyProto, typename PublicPrimitivesList,
              typename... PrivatePrimitives>
    KeyTypeInfo(
        PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                              List<PrivatePrimitives...>>* private_key_manager,
        KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
            public_key_manager,
        bool new_key_allowed)
        : key_manager_type_index_(
              std::type_index(typeid(*private_key_manager))),
          public_key_manager_type_index_(
              std::type_index(typeid(*public_key_manager))),
          new_key_allowed_(new_key_allowed),
          internal_key_factory_(
              absl::make_unique<internal::PrivateKeyFactoryImpl<
                  PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                  List<PrivatePrimitives...>, PublicPrimitivesList>>(
                  private_key_manager, public_key_manager)),
          key_factory_(internal_key_factory_.get()),
          key_deriver_(CreateDeriverFunctionFor(private_key_manager)),
          key_type_manager_(absl::WrapUnique(private_key_manager)) {
      // TODO(C++17) replace with a fold expression
      (void)std::initializer_list<int>{
          0, (primitive_to_manager_.emplace(
                  std::type_index(typeid(PrivatePrimitives)),
                  internal::MakePrivateKeyManager<PrivatePrimitives>(
                      private_key_manager, public_key_manager)),
              0)...};
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

    const absl::optional<std::type_index>& public_key_manager_type_index()
        const {
      return public_key_manager_type_index_;
    }

    bool new_key_allowed() const { return new_key_allowed_; }
    void set_new_key_allowed(bool b) { new_key_allowed_ = b; }

    const KeyFactory& key_factory() const { return *key_factory_; }

    const std::function<crypto::tink::util::StatusOr<
        google::crypto::tink::KeyData>(absl::string_view, InputStream*)>&
    key_deriver() const {
      return key_deriver_;
    }

   private:
    // dynamic std::type_index of the actual key manager class for which this
    // key was inserted.
    std::type_index key_manager_type_index_;
    // dynamic std::type_index of the public key manager corresponding to this
    // class, in case it was inserted using RegisterAsymmetricKeyManagers,
    // nullopt otherwise.
    absl::optional<std::type_index> public_key_manager_type_index_;

    // For each primitive, the corresponding names and key_manager.
    absl::flat_hash_map<std::type_index, std::unique_ptr<KeyManagerBase>>
        primitive_to_manager_;
    // Whether the key manager allows creating new keys.
    bool new_key_allowed_;
    // A factory constructed from an internal key manager. Owned version of
    // key_factory if constructed with a KeyTypeManager. This is nullptr if
    // constructed with a KeyManager.
    std::unique_ptr<const KeyFactory> internal_key_factory_;
    // Unowned copy of internal_key_factory, always different from
    // nullptr.
    const KeyFactory* key_factory_;
    // A function to call to derive a key. If the container was constructed with
    // a KeyTypeManager which has non-void keyformat type, this will forward to
    // the function DeriveKey of this container. Otherwise, the function is
    // 'empty', i.e., "key_deriver_" will cast to false when cast to a bool.
    std::function<crypto::tink::util::StatusOr<google::crypto::tink::KeyData>(
        absl::string_view, InputStream*)>
        key_deriver_;
    // The owned pointer in case we use a KeyTypeManager, nullptr if
    // constructed with a KeyManager.
    const std::shared_ptr<void> key_type_manager_;
  };

  class WrapperInfo {
   public:
    template <typename P, typename Q>
    explicit WrapperInfo(std::unique_ptr<PrimitiveWrapper<P, Q>> wrapper)
        : is_same_primitive_wrapping_(std::is_same<P, Q>::value),
          wrapper_type_index_(std::type_index(typeid(*wrapper))),
          q_type_index_(std::type_index(typeid(Q))) {
      auto keyset_wrapper_unique_ptr =
          absl::make_unique<KeysetWrapperImpl<P, Q>>(
              wrapper.get(), [](const google::crypto::tink::KeyData& key_data) {
                return RegistryImpl::GlobalInstance().GetPrimitive<P>(key_data);
              });
      keyset_wrapper_ = std::move(keyset_wrapper_unique_ptr);
      original_wrapper_ = std::move(wrapper);
    }

    template <typename Q>
    crypto::tink::util::StatusOr<const KeysetWrapper<Q>*> GetKeysetWrapper()
        const {
      if (q_type_index_ != std::type_index(typeid(Q))) {
        return crypto::tink::util::Status(
            absl::StatusCode::kInternal,
            "RegistryImpl::KeysetWrapper() called with wrong type");
      }
      return static_cast<KeysetWrapper<Q>*>(keyset_wrapper_.get());
    }

    template <typename P>
    crypto::tink::util::StatusOr<const PrimitiveWrapper<P, P>*>
    GetLegacyWrapper() const {
      if (!is_same_primitive_wrapping_) {
        // This happens if a user uses a legacy method (like Registry::Wrap)
        // directly or has a custom key manager for a primitive which has a
        // PrimitiveWrapper<P,Q> with P != Q.
        return crypto::tink::util::Status(
            absl::StatusCode::kFailedPrecondition,
            absl::StrCat("Cannot use primitive type ", typeid(P).name(),
                         " with a custom key manager."));
      }
      if (q_type_index_ != std::type_index(typeid(P))) {
        return crypto::tink::util::Status(
            absl::StatusCode::kInternal,
            "RegistryImpl::LegacyWrapper() called with wrong type");
      }
      return static_cast<const PrimitiveWrapper<P, P>*>(
          original_wrapper_.get());
    }

    // Returns true if the PrimitiveWrapper is the same class as the one used
    // to construct this WrapperInfo
    template <typename P, typename Q>
    bool HasSameType(const PrimitiveWrapper<P, Q>& wrapper) {
      return wrapper_type_index_ == std::type_index(typeid(wrapper));
    }

   private:
    bool is_same_primitive_wrapping_;
    // dynamic std::type_index of the actual PrimitiveWrapper<P,Q> class for
    // which this key was inserted.
    std::type_index wrapper_type_index_;
    // dynamic std::type_index of Q, when PrimitiveWrapper<P,Q> was inserted.
    std::type_index q_type_index_;
    // The primitive_wrapper passed in. We use a shared_ptr because
    // unique_ptr<void> is invalid.
    std::shared_ptr<void> original_wrapper_;
    // The keyset_wrapper_. We use a shared_ptr because unique_ptr<void> is
    // invalid.
    std::shared_ptr<void> keyset_wrapper_;
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

  template <class P>
  crypto::tink::util::StatusOr<const PrimitiveWrapper<P, P>*> GetLegacyWrapper()
      const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<const KeysetWrapper<P>*> GetKeysetWrapper() const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Returns the key type info for a given type URL. Since we never replace
  // key type infos, the pointers will stay valid for the lifetime of the
  // binary.
  crypto::tink::util::StatusOr<const KeyTypeInfo*> get_key_type_info(
      absl::string_view type_url) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Returns OK if the key manager with the given type index can be inserted
  // for type url type_url and parameter new_key_allowed. Otherwise returns
  // an error to be returned to the user.
  crypto::tink::util::Status CheckInsertable(
      absl::string_view type_url, const std::type_index& key_manager_type_index,
      bool new_key_allowed) const ABSL_SHARED_LOCKS_REQUIRED(maps_mutex_);

  mutable absl::Mutex maps_mutex_;
  // A map from the type_url to the given KeyTypeInfo. Once emplaced KeyTypeInfo
  // objects must remain valid throughout the life time of the binary. Hence,
  // one should /never/ replace any element of the KeyTypeInfo. This is because
  // get_key_type_manager() needs to guarantee that the returned
  // key_type_manager remains valid.
  // NOTE: We require pointer stability of the value, as get_key_type_info
  // returns a pointer which needs to stay alive.
  absl::flat_hash_map<std::string, KeyTypeInfo> type_url_to_info_
      ABSL_GUARDED_BY(maps_mutex_);
  // A map from the type_id to the corresponding wrapper.
  absl::flat_hash_map<std::type_index, WrapperInfo> primitive_to_wrapper_
      ABSL_GUARDED_BY(maps_mutex_);

  absl::flat_hash_map<std::string, LabelInfo> name_to_catalogue_map_
      ABSL_GUARDED_BY(maps_mutex_);

  mutable absl::Mutex monitoring_factory_mutex_;
  std::unique_ptr<crypto::tink::MonitoringClientFactory> monitoring_factory_
      ABSL_GUARDED_BY(monitoring_factory_mutex_);
};

template <class P>
crypto::tink::util::Status RegistryImpl::AddCatalogue(
    absl::string_view catalogue_name, Catalogue<P>* catalogue) {
  if (catalogue == nullptr) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
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
      return ToStatusF(absl::StatusCode::kAlreadyExists,
                       "A catalogue named '%s' has been already added.",
                       catalogue_name);
    }
  } else {
    name_to_catalogue_map_.emplace(
        std::piecewise_construct, std::forward_as_tuple(catalogue_name),
        std::forward_as_tuple(std::move(entry), std::type_index(typeid(P)),
                              typeid(P).name()));
  }
  return crypto::tink::util::OkStatus();
}

template <class P>
crypto::tink::util::StatusOr<const Catalogue<P>*> RegistryImpl::get_catalogue(
    absl::string_view catalogue_name) const {
  absl::MutexLock lock(&maps_mutex_);
  auto catalogue_entry = name_to_catalogue_map_.find(catalogue_name);
  if (catalogue_entry == name_to_catalogue_map_.end()) {
    return ToStatusF(absl::StatusCode::kNotFound,
                     "No catalogue named '%s' has been added.", catalogue_name);
  }
  if (catalogue_entry->second.type_id_name != typeid(P).name()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Wrong Primitive type for catalogue named '%s': "
                     "got '%s', expected '%s'",
                     catalogue_name, typeid(P).name(),
                     catalogue_entry->second.type_id_name);
  }
  return static_cast<Catalogue<P>*>(catalogue_entry->second.catalogue.get());
}

template <class P>
crypto::tink::util::Status RegistryImpl::RegisterKeyManager(
    KeyManager<P>* manager, bool new_key_allowed) {
  auto owned_manager = absl::WrapUnique(manager);
  if (owned_manager == nullptr) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      "Parameter 'manager' must be non-null.");
  }
  std::string type_url = owned_manager->get_key_type();
  if (!manager->DoesSupport(type_url)) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "The manager does not support type '%s'.", type_url);
  }
  absl::MutexLock lock(&maps_mutex_);
  crypto::tink::util::Status status = CheckInsertable(
      type_url, std::type_index(typeid(*owned_manager)), new_key_allowed);
  if (!status.ok()) return status;

  auto it = type_url_to_info_.find(type_url);
  if (it != type_url_to_info_.end()) {
    it->second.set_new_key_allowed(new_key_allowed);
  } else {
    type_url_to_info_.emplace(
        std::piecewise_construct, std::forward_as_tuple(type_url),
        std::forward_as_tuple(owned_manager.release(), new_key_allowed));
  }
  return crypto::tink::util::OkStatus();
}

template <class KeyProto, class KeyFormatProto, class PrimitiveList>
crypto::tink::util::Status RegistryImpl::RegisterKeyTypeManager(
    std::unique_ptr<KeyTypeManager<KeyProto, KeyFormatProto, PrimitiveList>>
        owned_manager,
    bool new_key_allowed) {
  if (owned_manager == nullptr) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      "Parameter 'manager' must be non-null.");
  }
  std::string type_url = owned_manager->get_key_type();
  absl::MutexLock lock(&maps_mutex_);

  // Check FIPS status
  internal::FipsCompatibility fips_compatible = owned_manager->FipsStatus();
  auto fips_status = internal::ChecksFipsCompatibility(fips_compatible);
  if (!fips_status.ok()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Failed registering the key manager for ",
                     typeid(*owned_manager).name(),
                     " as it is not FIPS compatible."));
  }

  crypto::tink::util::Status status = CheckInsertable(
      type_url, std::type_index(typeid(*owned_manager)), new_key_allowed);
  if (!status.ok()) return status;

  auto it = type_url_to_info_.find(type_url);
  if (it != type_url_to_info_.end()) {
    it->second.set_new_key_allowed(new_key_allowed);
  } else {
    type_url_to_info_.emplace(
        std::piecewise_construct, std::forward_as_tuple(type_url),
        std::forward_as_tuple(owned_manager.release(), new_key_allowed));
  }
  return crypto::tink::util::OkStatus();
}

template <class PrivateKeyProto, class KeyFormatProto, class PublicKeyProto,
          class PrivatePrimitivesList, class PublicPrimitivesList>
crypto::tink::util::Status RegistryImpl::RegisterAsymmetricKeyManagers(
    PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                          PrivatePrimitivesList>* private_key_manager,
    KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
        public_key_manager,
    bool new_key_allowed) ABSL_LOCKS_EXCLUDED(maps_mutex_) {
  auto owned_private_key_manager = absl::WrapUnique(private_key_manager);
  auto owned_public_key_manager = absl::WrapUnique(public_key_manager);
  if (private_key_manager == nullptr) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parameter 'private_key_manager' must be non-null.");
  }
  if (owned_public_key_manager == nullptr) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parameter 'public_key_manager' must be non-null.");
  }
  std::string private_type_url = private_key_manager->get_key_type();
  std::string public_type_url = public_key_manager->get_key_type();

  absl::MutexLock lock(&maps_mutex_);

  // Check FIPS status
  auto private_fips_status =
      internal::ChecksFipsCompatibility(private_key_manager->FipsStatus());

  if (!private_fips_status.ok()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Failed registering the key manager for ",
                     typeid(*private_key_manager).name(),
                     " as it is not FIPS compatible."));
  }

  auto public_fips_status =
      internal::ChecksFipsCompatibility(public_key_manager->FipsStatus());

  if (!public_fips_status.ok()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Failed registering the key manager for ",
                     typeid(*public_key_manager).name(),
                     " as it is not FIPS compatible."));
  }

  crypto::tink::util::Status status = CheckInsertable(
      private_type_url, std::type_index(typeid(*private_key_manager)),
      new_key_allowed);
  if (!status.ok()) return status;
  status = CheckInsertable(public_type_url,
                           std::type_index(typeid(*public_key_manager)),
                           new_key_allowed);
  if (!status.ok()) return status;

  if (private_type_url == public_type_url) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        "Passed in key managers must have different get_key_type() results.");
  }

  auto private_it = type_url_to_info_.find(private_type_url);
  auto public_it = type_url_to_info_.find(public_type_url);
  bool private_found = private_it != type_url_to_info_.end();
  bool public_found = public_it != type_url_to_info_.end();

  if (private_found && !public_found) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(
            "Private key manager corresponding to ",
            typeid(*private_key_manager).name(),
            " was previously registered, but key manager corresponding to ",
            typeid(*public_key_manager).name(),
            " was not, so it's impossible to register them jointly"));
  }
  if (!private_found && public_found) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Key manager corresponding to ",
                     typeid(*public_key_manager).name(),
                     " was previously registered, but private key manager "
                     "corresponding to ",
                     typeid(*private_key_manager).name(),
                     " was not, so it's impossible to register them jointly"));
  }

  if (private_found) {
    // implies public_found.
    if (!private_it->second.public_key_manager_type_index().has_value()) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("private key manager corresponding to ",
                       typeid(*private_key_manager).name(),
                       " is already registered without public key manager, "
                       "cannot be re-registered with public key manager. "));
    }
    if (*private_it->second.public_key_manager_type_index() !=
        std::type_index(typeid(*public_key_manager))) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat(
              "private key manager corresponding to ",
              typeid(*private_key_manager).name(),
              " is already registered with ",
              private_it->second.public_key_manager_type_index()->name(),
              ", cannot be re-registered with ",
              typeid(*public_key_manager).name()));
    }
  }

  if (!private_found) {
    // !public_found must hold.
    type_url_to_info_.emplace(
        std::piecewise_construct, std::forward_as_tuple(private_type_url),
        std::forward_as_tuple(owned_private_key_manager.release(),
                              owned_public_key_manager.get(), new_key_allowed));
    type_url_to_info_.emplace(
        std::piecewise_construct, std::forward_as_tuple(public_type_url),
        std::forward_as_tuple(owned_public_key_manager.release(),
                              new_key_allowed));
  } else {
    private_it->second.set_new_key_allowed(new_key_allowed);
  }

  return util::OkStatus();
}

template <class P, class Q>
crypto::tink::util::Status RegistryImpl::RegisterPrimitiveWrapper(
    PrimitiveWrapper<P, Q>* wrapper) {
  if (wrapper == nullptr) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      "Parameter 'wrapper' must be non-null.");
  }
  std::unique_ptr<PrimitiveWrapper<P, Q>> entry(wrapper);

  absl::MutexLock lock(&maps_mutex_);
  auto it = primitive_to_wrapper_.find(std::type_index(typeid(Q)));
  if (it != primitive_to_wrapper_.end()) {
    if (!it->second.HasSameType(*wrapper)) {
      return util::Status(
          absl::StatusCode::kAlreadyExists,
          "A wrapper named for this primitive has already been added.");
    }
    return crypto::tink::util::OkStatus();
  }
  primitive_to_wrapper_.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(std::type_index(typeid(Q))),
      std::forward_as_tuple(std::move(entry)));
  return crypto::tink::util::OkStatus();
}

template <class P>
crypto::tink::util::StatusOr<const KeyManager<P>*>
RegistryImpl::get_key_manager(absl::string_view type_url) const {
  absl::MutexLock lock(&maps_mutex_);
  auto it = type_url_to_info_.find(type_url);
  if (it == type_url_to_info_.end()) {
    return ToStatusF(absl::StatusCode::kNotFound,
                     "No manager for type '%s' has been registered.", type_url);
  }
  return it->second.get_key_manager<P>(type_url);
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
    absl::string_view type_url, const portable_proto::MessageLite& key) const {
  auto key_manager_result = get_key_manager<P>(type_url);
  if (key_manager_result.ok()) {
    return key_manager_result.ValueOrDie()->GetPrimitive(key);
  }
  return key_manager_result.status();
}

template <class P>
crypto::tink::util::StatusOr<const PrimitiveWrapper<P, P>*>
RegistryImpl::GetLegacyWrapper() const {
  absl::MutexLock lock(&maps_mutex_);
  auto it = primitive_to_wrapper_.find(std::type_index(typeid(P)));
  if (it == primitive_to_wrapper_.end()) {
    return util::Status(
        absl::StatusCode::kNotFound,
        absl::StrCat("No wrapper registered for type ", typeid(P).name()));
  }
  return it->second.GetLegacyWrapper<P>();
}

template <class P>
crypto::tink::util::StatusOr<const KeysetWrapper<P>*>
RegistryImpl::GetKeysetWrapper() const {
  absl::MutexLock lock(&maps_mutex_);
  auto it = primitive_to_wrapper_.find(std::type_index(typeid(P)));
  if (it == primitive_to_wrapper_.end()) {
    return util::Status(
        absl::StatusCode::kNotFound,
        absl::StrCat("No wrapper registered for type ", typeid(P).name()));
  }
  return it->second.GetKeysetWrapper<P>();
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::Wrap(
    std::unique_ptr<PrimitiveSet<P>> primitive_set) const {
  if (primitive_set == nullptr) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parameter 'primitive_set' must be non-null.");
  }
  util::StatusOr<const PrimitiveWrapper<P, P>*> wrapper_result =
      GetLegacyWrapper<P>();
  if (!wrapper_result.ok()) {
    return wrapper_result.status();
  }
  crypto::tink::util::StatusOr<std::unique_ptr<P>> primitive_result =
      wrapper_result.ValueOrDie()->Wrap(std::move(primitive_set));
  return std::move(primitive_result);
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::WrapKeyset(
    const google::crypto::tink::Keyset& keyset) const {
  util::StatusOr<const KeysetWrapper<P>*> wrapper_result =
      GetKeysetWrapper<P>();
  if (!wrapper_result.ok()) {
    return wrapper_result.status();
  }
  crypto::tink::util::StatusOr<std::unique_ptr<P>> primitive_result =
      wrapper_result.ValueOrDie()->Wrap(keyset);
  return std::move(primitive_result);
}

inline crypto::tink::util::Status RegistryImpl::RestrictToFipsIfEmpty() const {
  absl::MutexLock lock(&maps_mutex_);
  if (type_url_to_info_.empty()) {
    SetFipsRestricted();
    return util::OkStatus();
  }
  return util::Status(absl::StatusCode::kInternal,
                      "Could not set FIPS only mode. Registry is not empty.");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_REGISTRY_IMPL_H_
