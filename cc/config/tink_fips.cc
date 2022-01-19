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

#include "tink/internal/fips_utils.h"
#include "tink/internal/registry_impl.h"
#include "tink/util/status.h"


namespace crypto {
namespace tink {

bool IsFipsModeEnabled() {
  return internal::IsFipsModeEnabled();
}

crypto::tink::util::Status RestrictToFips() {
  return internal::RegistryImpl::GlobalInstance().RestrictToFipsIfEmpty();
}

}  // namespace tink
}  // namespace crypto
