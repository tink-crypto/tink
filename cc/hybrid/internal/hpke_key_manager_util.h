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

#ifndef TINK_HYBRID_INTERNAL_HPKE_KEY_MANAGER_UTIL_H_
#define TINK_HYBRID_INTERNAL_HPKE_KEY_MANAGER_UTIL_H_

#include <string>

#include "tink/util/status.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

crypto::tink::util::Status ValidateParams(
    const google::crypto::tink::HpkeParams& params);

crypto::tink::util::Status ValidateKeyAndVersion(
    const google::crypto::tink::HpkePublicKey& key, uint32_t max_key_version);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_KEY_MANAGER_UTIL_H_
