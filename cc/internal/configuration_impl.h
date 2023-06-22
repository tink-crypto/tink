// Copyright 2023 Google LLC
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

#ifndef TINK_INTERNAL_CONFIGURATION_IMPL_H_
#define TINK_INTERNAL_CONFIGURATION_IMPL_H_

#include "tink/configuration.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"

namespace crypto {
namespace tink {
namespace internal {

class ConfigurationImpl {
 public:
  template <class PW>
  static crypto::tink::util::Status AddPrimitiveWrapper(
      std::unique_ptr<PW> wrapper, crypto::tink::Configuration& config) {
    // We must specify `primitive_getter` here and no later, since the
    // corresponding get function, KeysetWrapper::WrapKeyset, does not have
    // access to PW::InputPrimitive. `primitive_getter` is stored in the key
    // manager, which is currently stored in `config.key_type_info_store_`.
    // TODO(b/284084337): Move primitive getter out of key manager.
    std::function<crypto::tink::util::StatusOr<
        std::unique_ptr<typename PW::InputPrimitive>>(
        const google::crypto::tink::KeyData& key_data)>
        primitive_getter =
            [&config](const google::crypto::tink::KeyData& key_data)
        -> crypto::tink::util::StatusOr<
            std::unique_ptr<typename PW::InputPrimitive>> {
      crypto::tink::util::StatusOr<
          const crypto::tink::internal::KeyTypeInfoStore::Info*>
          info = config.key_type_info_store_.Get(key_data.type_url());
      if (!info.ok()) {
        return info.status();
      }

      crypto::tink::util::StatusOr<
          const crypto::tink::KeyManager<typename PW::InputPrimitive>*>
          key_manager = (*info)->get_key_manager<typename PW::InputPrimitive>(
              key_data.type_url());
      if (!key_manager.ok()) {
        return key_manager.status();
      }

      return (*key_manager)->GetPrimitive(key_data);
    };

    return config.keyset_wrapper_store_
        .Add<typename PW::InputPrimitive, typename PW::Primitive>(
            std::move(wrapper), primitive_getter);
  }

  template <class KM>
  static crypto::tink::util::Status AddKeyTypeManager(
      std::unique_ptr<KM> key_manager, crypto::tink::Configuration& config) {
    return config.key_type_info_store_.AddKeyTypeManager(
        std::move(key_manager), /*new_key_allowed=*/true);
  }

  template <class PrivateKM, class PublicKM>
  static crypto::tink::util::Status AddAsymmetricKeyManagers(
      std::unique_ptr<PrivateKM> private_key_manager,
      std::unique_ptr<PublicKM> public_key_manager,
      crypto::tink::Configuration& config) {
    return config.key_type_info_store_.AddAsymmetricKeyTypeManagers(
        std::move(private_key_manager), std::move(public_key_manager),
        /*new_key_allowed=*/true);
  }

  static crypto::tink::util::StatusOr<
      const crypto::tink::internal::KeyTypeInfoStore*>
  GetKeyTypeInfoStore(const crypto::tink::Configuration& config) {
    return &config.key_type_info_store_;
  }

  static crypto::tink::util::StatusOr<
      const crypto::tink::internal::KeysetWrapperStore*>
  GetKeysetWrapperStore(const crypto::tink::Configuration& config) {
    return &config.keyset_wrapper_store_;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_CONFIGURATION_IMPL_H_
