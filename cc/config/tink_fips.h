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
#include "tink/internal/fips_utils.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

// This function will return true if Tink has been built in FIPS mode or if
// the FIPS restrictions have been enabled at runtime.
bool IsFipsModeEnabled();

// Enables the FIPS restrictions for the registry and subtle primitives. If Tink
// has been built in FIPS this is redundant. This method must be called before
// handling any key material or calling any of the functions in subtle.
crypto::tink::util::Status RestrictToFips();

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CONFIG_TINK_FIPS_H_
