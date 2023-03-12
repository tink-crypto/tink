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
#include "tink/internal/registry_impl.h"

namespace crypto {
namespace tink {
namespace internal {

class ConfigurationImpl {
 public:
  static const RegistryImpl& get_registry(
      const crypto::tink::Configuration& config) {
    return config.registry_;
  }

  template <class W>
  static crypto::tink::util::Status RegisterPrimitiveWrapper(
      std::unique_ptr<W> wrapper, crypto::tink::Configuration& config) {
    return config.registry_.RegisterPrimitiveWrapper(wrapper.release());
  }

  template <class KM>
  static crypto::tink::util::Status RegisterKeyTypeManager(
      std::unique_ptr<KM> key_manager, crypto::tink::Configuration& config) {
    return config.registry_.RegisterKeyTypeManager<typename KM::KeyProto,
                                                   typename KM::KeyFormatProto,
                                                   typename KM::PrimitiveList>(
        std::move(key_manager),
        /*new_key_allowed=*/true);
  }

  template <class PrivateKM, class PublicKM>
  static crypto::tink::util::Status RegisterAsymmetricKeyManagers(
      std::unique_ptr<PrivateKM> private_key_manager,
      std::unique_ptr<PublicKM> public_key_manager,
      crypto::tink::Configuration& config) {
    return config.registry_.RegisterAsymmetricKeyManagers(
        private_key_manager.release(), public_key_manager.release(),
        /*new_key_allowed=*/true);
  }
};
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_CONFIGURATION_IMPL_H_
