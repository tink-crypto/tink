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
#ifndef TINK_CONFIG_TINK_FIPS_H_
#define TINK_CONFIG_TINK_FIPS_H_

#include "absl/base/attributes.h"
#include "openssl/crypto.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

// This flag indicates whether Tink was build in FIPS only mode. If the flag
// is set, then usage of algorithms will be restricted to algorithms which
// utilize the FIPS validated BoringCrypto module.
ABSL_CONST_INIT extern const bool kUseOnlyFips;

// Should be used to indicate whether an algorithm can be used in FIPS only
// mode or not.
enum class FipsCompatibility {
  kNotFips = 0,  // The algorithm can not use a FIPS validated implementation.
  kRequiresBoringCrypto,  // The algorithm requires BoringCrypto to use a FIPS
                          // validated implementation.
};

// Allows to check for a cryptographic algorithm whether it is available in
// the FIPS only mode, based on it's FipsCompatibility flag. If FIPS only
// mode is enabled this will return an INTERNAL error if:
// 1) The algorithm has no FIPS support.
// 2) The algorithm has FIPS support, but BoringSSL has not been compiled with
//    the BoringCrypto module.
crypto::tink::util::Status ChecksFipsCompatibility(
    FipsCompatibility fips_status);

// Utility function wich calls CheckFipsCompatibility(T::kFipsStatus).
template <class T>
crypto::tink::util::Status CheckFipsCompatibility() {
  return ChecksFipsCompatibility(T::kFipsStatus);
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CONFIG_TINK_FIPS_H_
