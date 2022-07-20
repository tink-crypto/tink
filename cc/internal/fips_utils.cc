// Copyright 2021 Google LLC
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

#include "tink/internal/fips_utils.h"

#include <atomic>

#include "absl/status/status.h"
#include "openssl/crypto.h"

namespace crypto {
namespace tink {
namespace internal {

#ifdef TINK_USE_ONLY_FIPS
ABSL_CONST_INIT const bool kUseOnlyFips = true;
#else
ABSL_CONST_INIT const bool kUseOnlyFips = false;
#endif

static std::atomic<bool> is_fips_restricted(false);

void SetFipsRestricted() { is_fips_restricted = true; }

void UnSetFipsRestricted() { is_fips_restricted = false; }

crypto::tink::util::Status ChecksFipsCompatibility(
    FipsCompatibility fips_status) {
  switch (fips_status) {
    case FipsCompatibility::kNotFips:
      if (IsFipsModeEnabled()) {
        return util::Status(absl::StatusCode::kInternal,
                            "Primitive not available in FIPS only mode.");
      } else {
        return util::OkStatus();
      }
    case FipsCompatibility::kRequiresBoringCrypto:
      if ((IsFipsModeEnabled()) && !FIPS_mode()) {
        return util::Status(
            absl::StatusCode::kInternal,
            "BoringSSL not built with the BoringCrypto module. If you want to "
            "use FIPS only mode you have to build BoringSSL in FIPS Mode.");

      } else {
        return util::OkStatus();
      }
    default:
      return util::Status(absl::StatusCode::kInternal,
                          "Could not determine FIPS status.");
  }
}

bool IsFipsModeEnabled() { return kUseOnlyFips || is_fips_restricted; }

}  // namespace internal
}  // namespace tink
}  // namespace crypto
