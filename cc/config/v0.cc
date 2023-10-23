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

#include "tink/config/v0.h"

#include "absl/log/check.h"
#include "tink/aead/internal/config_v0.h"
#include "tink/configuration.h"
#include "tink/daead/internal/config_v0.h"
#include "tink/hybrid/internal/config_v0.h"
#include "tink/internal/configuration_impl.h"
#include "tink/mac/internal/config_v0.h"
#include "tink/prf/internal/config_v0.h"
#include "tink/signature/internal/config_v0.h"
#include "tink/streamingaead/internal/config_v0.h"

namespace crypto {
namespace tink {

const Configuration& ConfigV0() {
  static const Configuration* instance = [] {
    static Configuration* config = new Configuration();
    CHECK_OK(internal::AddMacV0(*config));
    CHECK_OK(internal::AddAeadV0(*config));
    CHECK_OK(internal::AddDeterministicAeadV0(*config));
    CHECK_OK(internal::AddStreamingAeadV0(*config));
    CHECK_OK(internal::AddHybridConfigV0(*config));
    CHECK_OK(internal::AddPrfV0(*config));
    CHECK_OK(internal::AddSignatureV0(*config));
    return config;
  }();
  return *instance;
}

}  // namespace tink
}  // namespace crypto
