// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
#include "tink/prf/prf_config.h"

#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/prf_set_wrapper.h"
#include "tink/registry.h"

namespace crypto {
namespace tink {

crypto::tink::util::Status PrfConfig::Register() {
  auto status = Registry::RegisterKeyTypeManager(
      absl::make_unique<HkdfPrfKeyManager>(), true);
  if (!status.ok()) {
    return status;
  }
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<HmacPrfKeyManager>(), true);
  if (!status.ok()) {
    return status;
  }
  status = Registry::RegisterKeyTypeManager(
      absl::make_unique<AesCmacPrfKeyManager>(), true);
  if (!status.ok()) {
    return status;
  }
  return Registry::RegisterPrimitiveWrapper(absl::make_unique<PrfSetWrapper>());
}

}  // namespace tink
}  // namespace crypto
