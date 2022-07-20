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

#ifndef TINK_HYBRID_INTERNAL_HPKE_UTIL_BORINGSSL_H_
#define TINK_HYBRID_INTERNAL_HPKE_UTIL_BORINGSSL_H_

#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<const EVP_HPKE_KEM*> KemParam(
    const google::crypto::tink::HpkeKem& kem);

util::StatusOr<const EVP_HPKE_KEM*> KemParam(const HpkeParams& params);

util::StatusOr<const EVP_HPKE_KEM*> KemParam(
    const google::crypto::tink::HpkeParams& params);

util::StatusOr<const EVP_HPKE_KDF*> KdfParam(const HpkeParams& params);

util::StatusOr<const EVP_HPKE_KDF*> KdfParam(
    const google::crypto::tink::HpkeParams& params);

util::StatusOr<const EVP_HPKE_AEAD*> AeadParam(const HpkeParams& params);

util::StatusOr<const EVP_HPKE_AEAD*> AeadParam(
    const google::crypto::tink::HpkeParams& params);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_UTIL_BORINGSSL_H_
