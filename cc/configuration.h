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

#ifndef TINK_CONFIGURATION_H_
#define TINK_CONFIGURATION_H_

#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"

namespace crypto {
namespace tink {

namespace internal {
class ConfigurationImpl;
}

// Configuration used to generate primitives using stored primitive wrappers and
// key type managers.
class Configuration {
 public:
  Configuration() = default;

  // Not copyable or movable.
  Configuration(const Configuration&) = delete;
  Configuration& operator=(const Configuration&) = delete;

 private:
  friend class internal::ConfigurationImpl;

  // When true, Configuration is in global registry mode. For `some_fn(config)`
  // with a `config` parameter, this indicates to `some_fn` to use
  // crypto::tink::Registry directly.
  bool global_registry_mode_ = false;

  crypto::tink::internal::KeyTypeInfoStore key_type_info_store_;
  crypto::tink::internal::KeysetWrapperStore keyset_wrapper_store_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CONFIGURATION_H_
