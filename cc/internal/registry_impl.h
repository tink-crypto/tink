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
#include <memory>
#include <string>
#include <type_traits>
#include <typeindex>
#include <typeinfo>
#include <utility>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/meta/type_traits.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/input_stream.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper.h"
#include "tink/internal/keyset_wrapper_impl.h"
#include "tink/key_manager.h"
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
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

  // Registers the given 'manager' for the key type 'manager->get_key_type()'.
  // Takes ownership of 'manager', which must be non-nullptr. KeyManager is the
  // legacy/internal version of KeyTypeManager.
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

  // Takes ownership of 'private_manager' and 'public_manager'. Both must be
  // non-nullptr.
  template <class PrivateKeyProto, class KeyFormatProto, class PublicKeyProto,
            class PrivatePrimitivesList, class PublicPrimitivesList>
  crypto::tink::util::Status RegisterAsymmetricKeyManagers(
      PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                            PrivatePrimitivesList>* private_manager,
      KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
          public_manager,
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

  // Wraps a `keyset` and annotates it with `annotations`.
  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> WrapKeyset(
      const google::crypto::tink::Keyset& keyset,
      const absl::flat_hash_map<std::string, std::string>& annotations) const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  crypto::tink::util::StatusOr<google::crypto::tink::KeyData> DeriveKey(
      const google::crypto::tink::KeyTemplate& key_template,
      InputStream* randomness) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  void Reset() ABSL_LOCKS_EXCLUDED(maps_mutex_, monitoring_factory_mutex_);

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
  class WrapperInfo {
   public:
    template <typename P, typename Q>
    explicit WrapperInfo(
        std::unique_ptr<PrimitiveWrapper<P, Q>> wrapper,
        std::function<crypto::tink::util::StatusOr<std::unique_ptr<P>>(
            const google::crypto::tink::KeyData& key_data)>
            primitive_getter)
        : is_same_primitive_wrapping_(std::is_same<P, Q>::value),
          wrapper_type_index_(std::type_index(typeid(*wrapper))),
          q_type_index_(std::type_index(typeid(Q))) {
      keyset_wrapper_ = absl::make_unique<KeysetWrapperImpl<P, Q>>(
          wrapper.get(), primitive_getter);
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

  template <class P>
  crypto::tink::util::StatusOr<const PrimitiveWrapper<P, P>*> GetLegacyWrapper()
      const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  template <class P>
  crypto::tink::util::StatusOr<const KeysetWrapper<P>*> GetKeysetWrapper() const
      ABSL_LOCKS_EXCLUDED(maps_mutex_);

  // Returns the key type info for a given type URL. Since we never replace
  // key type infos, the pointers will stay valid for the lifetime of the
  // binary.
  crypto::tink::util::StatusOr<const KeyTypeInfoStore::Info*> get_key_type_info(
      absl::string_view type_url) const ABSL_LOCKS_EXCLUDED(maps_mutex_);

  mutable absl::Mutex maps_mutex_;
  // Stores information about key types constructed from their KeyTypeManager or
  // KeyManager.
  // Once inserted, KeyTypeInfoStore::Info objects must remain valid for the
  // lifetime of the binary, and the Info object's pointer stability is
  // required. Elements in Info, which include the KeyTypeManager or KeyManager,
  // must not be replaced.
  KeyTypeInfoStore key_type_info_store_ ABSL_GUARDED_BY(maps_mutex_);
  // A map from the type_id to the corresponding wrapper.
  absl::flat_hash_map<std::type_index, std::unique_ptr<WrapperInfo>>
      primitive_to_wrapper_ ABSL_GUARDED_BY(maps_mutex_);

  mutable absl::Mutex monitoring_factory_mutex_;
  std::unique_ptr<crypto::tink::MonitoringClientFactory> monitoring_factory_
      ABSL_GUARDED_BY(monitoring_factory_mutex_);
};

template <class P>
crypto::tink::util::Status RegistryImpl::RegisterKeyManager(
    KeyManager<P>* manager, bool new_key_allowed) {
  auto owned_manager = absl::WrapUnique(manager);
  if (manager == nullptr) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      "Parameter 'manager' must be non-null.");
  }
  absl::MutexLock lock(&maps_mutex_);
  return key_type_info_store_.AddKeyManager(std::move(owned_manager),
                                            new_key_allowed);
}

template <class KeyProto, class KeyFormatProto, class PrimitiveList>
crypto::tink::util::Status RegistryImpl::RegisterKeyTypeManager(
    std::unique_ptr<KeyTypeManager<KeyProto, KeyFormatProto, PrimitiveList>>
        manager,
    bool new_key_allowed) {
  if (manager == nullptr) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      "Parameter 'manager' must be non-null.");
  }
  absl::MutexLock lock(&maps_mutex_);
  return key_type_info_store_.AddKeyTypeManager(std::move(manager),
                                                new_key_allowed);
}

template <class PrivateKeyProto, class KeyFormatProto, class PublicKeyProto,
          class PrivatePrimitivesList, class PublicPrimitivesList>
crypto::tink::util::Status RegistryImpl::RegisterAsymmetricKeyManagers(
    PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                          PrivatePrimitivesList>* private_manager,
    KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>* public_manager,
    bool new_key_allowed) ABSL_LOCKS_EXCLUDED(maps_mutex_) {
  auto owned_private_manager = absl::WrapUnique(private_manager);
  auto owned_public_manager = absl::WrapUnique(public_manager);

  if (private_manager == nullptr) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parameter 'private_manager' must be non-null.");
  }
  if (public_manager == nullptr) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parameter 'public_manager' must be non-null.");
  }

  absl::MutexLock lock(&maps_mutex_);
  return key_type_info_store_.AddAsymmetricKeyTypeManagers(
      std::move(owned_private_manager), std::move(owned_public_manager),
      new_key_allowed);
}

template <class P, class Q>
crypto::tink::util::Status RegistryImpl::RegisterPrimitiveWrapper(
    PrimitiveWrapper<P, Q>* wrapper) {
  if (wrapper == nullptr) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      "Parameter 'wrapper' must be non-null.");
  }
  std::unique_ptr<PrimitiveWrapper<P, Q>> owned_wrapper(wrapper);

  absl::MutexLock lock(&maps_mutex_);
  auto it = primitive_to_wrapper_.find(std::type_index(typeid(Q)));
  if (it != primitive_to_wrapper_.end()) {
    if (!it->second->HasSameType(*wrapper)) {
      return util::Status(
          absl::StatusCode::kAlreadyExists,
          "A wrapper named for this primitive has already been added.");
    }
    return crypto::tink::util::OkStatus();
  }
  std::function<crypto::tink::util::StatusOr<std::unique_ptr<P>>(
      const google::crypto::tink::KeyData& key_data)>
      primitive_getter = [this](const google::crypto::tink::KeyData& key_data) {
        return this->GetPrimitive<P>(key_data);
      };
  auto wrapper_info = absl::make_unique<WrapperInfo>(std::move(owned_wrapper),
                                                     primitive_getter);
  primitive_to_wrapper_.insert(
      {std::type_index(typeid(Q)), std::move(wrapper_info)});
  return crypto::tink::util::OkStatus();
}

template <class P>
crypto::tink::util::StatusOr<const KeyManager<P>*>
RegistryImpl::get_key_manager(absl::string_view type_url) const {
  absl::MutexLock lock(&maps_mutex_);
  util::StatusOr<const KeyTypeInfoStore::Info*> info =
      key_type_info_store_.Get(type_url);
  if (!info.ok()) {
    return info.status();
  }
  return (*info)->get_key_manager<P>(type_url);
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::GetPrimitive(
    const google::crypto::tink::KeyData& key_data) const {
  auto key_manager_result = get_key_manager<P>(key_data.type_url());
  if (key_manager_result.ok()) {
    return key_manager_result.value()->GetPrimitive(key_data);
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
  return it->second->GetLegacyWrapper<P>();
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
  return it->second->GetKeysetWrapper<P>();
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
  return wrapper_result.value()->Wrap(std::move(primitive_set));
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> RegistryImpl::WrapKeyset(
    const google::crypto::tink::Keyset& keyset,
    const absl::flat_hash_map<std::string, std::string>& annotations) const {
  crypto::tink::util::StatusOr<const KeysetWrapper<P>*> keyset_wrapper =
      GetKeysetWrapper<P>();
  if (!keyset_wrapper.ok()) {
    return keyset_wrapper.status();
  }
  return (*keyset_wrapper)->Wrap(keyset, annotations);
}

inline crypto::tink::util::Status RegistryImpl::RestrictToFipsIfEmpty() const {
  absl::MutexLock lock(&maps_mutex_);
  // If we are already in FIPS mode, then do nothing..
  if (IsFipsModeEnabled()) {
    return util::OkStatus();
  }
  if (key_type_info_store_.IsEmpty()) {
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
