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

#ifndef THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_SUBTLE_CECPQ2_SUBTLE_BORINGSSL_UTIL_H_
#define THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_SUBTLE_CECPQ2_SUBTLE_BORINGSSL_UTIL_H_

#include "openssl/hrss.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace pqc {

struct HrssKeyPair {
  crypto::tink::util::SecretData hrss_private_key_seed;
  std::string hrss_public_key_marshaled;
};

struct EccKeyPair {
  std::string pub_x;
  std::string pub_y;
  util::SecretData priv;
};

struct Cecpq2KeyPair {
  struct HrssKeyPair hrss_key_pair;
  struct EccKeyPair x25519_key_pair;
};

// This is an utility function that generates a new HRSS key pair from a high
// entropy seed (hrss_key_entropy). This function is expected to be called from
// a key manager class, which will take care of generating a high entropy seed.
crypto::tink::util::StatusOr<HrssKeyPair> GenerateHrssKeyPair(
    util::SecretData hrss_key_entropy);

// This method performs CECPQ2 (HRSS and X25519) key generation,
// and HRSS public key marshaling.
crypto::tink::util::StatusOr<crypto::tink::pqc::Cecpq2KeyPair>
GenerateCecpq2Keypair(subtle::EllipticCurveType curve_type);

}  // namespace pqc
}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_SUBTLE_CECPQ2_SUBTLE_BORINGSSL_UTIL_H_
