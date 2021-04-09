// Copyright 2020 Google LLC
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
#include "tink/config/tink_fips.h"

namespace crypto {
namespace tink {

#ifdef TINK_USE_ONLY_FIPS
const bool kUseOnlyFips = true;
#else
const bool kUseOnlyFips = false;
#endif

crypto::tink::util::Status ChecksFipsCompatibility(
    FipsCompatibility fips_status) {
  switch (fips_status) {
    case FipsCompatibility::kNotFips:
      if (kUseOnlyFips) {
        return util::Status(util::error::INTERNAL,
                            "Primitive not available in FIPS only mode.");
      } else {
        return util::OkStatus();
      }
    case FipsCompatibility::kRequiresBoringCrypto:
      if (kUseOnlyFips && !FIPS_mode()) {
        return util::Status(
            util::error::INTERNAL,
            "BoringSSL not built with the BoringCrypto module. If you want to "
            "use "
            "FIPS only mode you have to build BoringSSL in FIPS Mode.");

      } else {
        return util::OkStatus();
      }
    default:
      return util::Status(util::error::INTERNAL,
                          "Could not determine FIPS status.");
  }
}

}  // namespace tink
}  // namespace crypto
