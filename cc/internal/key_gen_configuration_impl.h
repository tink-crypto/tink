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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_KEY_GEN_CONFIGURATION_IMPL_H_
#define TINK_INTERNAL_KEY_GEN_CONFIGURATION_IMPL_H_

#include "tink/internal/key_type_info_store.h"
#include "tink/key_gen_configuration.h"

namespace crypto {
namespace tink {
namespace internal {

class KeyGenConfigurationImpl {
 public:
  template <class KM>
  static crypto::tink::util::Status AddKeyTypeManager(
      std::unique_ptr<KM> key_manager,
      crypto::tink::KeyGenConfiguration& config) {
    return config.key_type_info_store_.AddKeyTypeManager(
        std::move(key_manager), /*new_key_allowed=*/true);
  }

  template <class PrivateKM, class PublicKM>
  static crypto::tink::util::Status AddAsymmetricKeyManagers(
      std::unique_ptr<PrivateKM> private_key_manager,
      std::unique_ptr<PublicKM> public_key_manager,
      crypto::tink::KeyGenConfiguration& config) {
    return config.key_type_info_store_.AddAsymmetricKeyTypeManagers(
        std::move(private_key_manager), std::move(public_key_manager),
        /*new_key_allowed=*/true);
  }

  static crypto::tink::util::StatusOr<
      const crypto::tink::internal::KeyTypeInfoStore*>
  GetKeyTypeInfoStore(const crypto::tink::KeyGenConfiguration& config) {
    return &config.key_type_info_store_;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_GEN_CONFIGURATION_IMPL_H_
