// Copyright 2019 Google LLC
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

#include "tink/cc/cc_tink_config.h"

#include <utility>

#include "tink/config/tink_config.h"
#include "tink/util/status.h"
#include "tink/cc/pybind/tink_exception.h"

namespace crypto {
namespace tink {

void CcTinkConfigRegister() {
  util::Status result = TinkConfig::Register();
  if (!result.ok()) {
    throw pybind11::google_tink::TinkException(result);
  }
}

}  // namespace tink
}  // namespace crypto
