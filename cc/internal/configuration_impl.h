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

#include <functional>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/configuration.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key_manager.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr absl::string_view kConfigurationImplErr =
    "Use crypto::tink::Registry instead when in global registry mode.";

class ConfigurationImpl {
 public:
  template <class PW>
  static crypto::tink::util::Status AddPrimitiveWrapper(
      std::unique_ptr<PW> wrapper, crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kConfigurationImplErr);
    }

    // `primitive_getter` must be defined here, as PW::InputPrimitive is not
    // accessible later.
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
      return (*info)->GetPrimitive<typename PW::InputPrimitive>(key_data);
    };

    return config.keyset_wrapper_store_
        .Add<typename PW::InputPrimitive, typename PW::Primitive>(
            std::move(wrapper), primitive_getter);
  }

  template <class KM>
  static crypto::tink::util::Status AddKeyTypeManager(
      std::unique_ptr<KM> key_manager, crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kConfigurationImplErr);
    }
    return config.key_type_info_store_.AddKeyTypeManager(
        std::move(key_manager), /*new_key_allowed=*/true);
  }

  template <class PrivateKM, class PublicKM>
  static crypto::tink::util::Status AddAsymmetricKeyManagers(
      std::unique_ptr<PrivateKM> private_key_manager,
      std::unique_ptr<PublicKM> public_key_manager,
      crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kConfigurationImplErr);
    }
    return config.key_type_info_store_.AddAsymmetricKeyTypeManagers(
        std::move(private_key_manager), std::move(public_key_manager),
        /*new_key_allowed=*/true);
  }

  static crypto::tink::util::StatusOr<
      const crypto::tink::internal::KeyTypeInfoStore*>
  GetKeyTypeInfoStore(const crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kConfigurationImplErr);
    }
    return &config.key_type_info_store_;
  }

  static crypto::tink::util::StatusOr<
      const crypto::tink::internal::KeysetWrapperStore*>
  GetKeysetWrapperStore(const crypto::tink::Configuration& config) {
    if (config.global_registry_mode_) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        kConfigurationImplErr);
    }
    return &config.keyset_wrapper_store_;
  }

  // `config` can be set to global registry mode only if empty.
  static crypto::tink::util::Status SetGlobalRegistryMode(
      crypto::tink::Configuration& config) {
    if (!config.key_type_info_store_.IsEmpty() ||
        !config.keyset_wrapper_store_.IsEmpty()) {
      return crypto::tink::util::Status(absl::StatusCode::kFailedPrecondition,
                                        "Using the global registry is only "
                                        "allowed when Configuration is empty.");
    }
    config.global_registry_mode_ = true;
    return crypto::tink::util::OkStatus();
  }

  static bool IsInGlobalRegistryMode(
      const crypto::tink::Configuration& config) {
    return config.global_registry_mode_;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_CONFIGURATION_IMPL_H_
