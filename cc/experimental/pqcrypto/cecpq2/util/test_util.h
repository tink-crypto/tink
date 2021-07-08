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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_CECPQ2_UTIL_TEST_UTIL_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_CECPQ2_UTIL_TEST_UTIL_H_

#include "proto/experimental/pqcrypto/cecpq2_aead_hkdf.pb.h"

namespace crypto {
namespace tink {
namespace test {

google::crypto::tink::Cecpq2AeadHkdfPrivateKey GetCecpq2AeadHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type);

google::crypto::tink::Cecpq2AeadHkdfPrivateKey GetCecpq2AesGcmHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_gcm_key_size);

google::crypto::tink::Cecpq2AeadHkdfPrivateKey GetCecpq2AesCtrHmacHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_ctr_key_size,
    uint32_t aes_ctr_iv_size, google::crypto::tink::HashType hmac_hash_type,
    uint32_t hmac_tag_size, uint32_t hmac_key_size);

google::crypto::tink::Cecpq2AeadHkdfPrivateKey
GetCecpq2XChaCha20Poly1305HkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type);

}  // namespace test
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_CECPQ2_UTIL_TEST_UTIL_H_
