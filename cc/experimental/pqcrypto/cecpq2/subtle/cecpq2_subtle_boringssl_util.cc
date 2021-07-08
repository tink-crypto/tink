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

#include "experimental/pqcrypto/cecpq2/subtle/cecpq2_subtle_boringssl_util.h"

#include "openssl/curve25519.h"
#include "openssl/hrss.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace pqc {

crypto::tink::util::StatusOr<crypto::tink::pqc::HrssKeyPair>
GenerateHrssKeyPair(util::SecretData hrss_key_entropy) {
  crypto::tink::pqc::HrssKeyPair hrss_key_pair;
  hrss_key_pair.hrss_private_key_seed = std::move(hrss_key_entropy);

  struct HRSS_public_key hrss_public_key;
  util::SecretUniquePtr<struct HRSS_private_key> hrss_private_key =
      util::MakeSecretUniquePtr<struct HRSS_private_key>();

  // Generating a HRSS key pair
  HRSS_generate_key(&hrss_public_key, hrss_private_key.get(),
                    hrss_key_pair.hrss_private_key_seed.data());

  // Marshalling the HRSS public key
  crypto::tink::subtle::ResizeStringUninitialized(
      &(hrss_key_pair.hrss_public_key_marshaled), HRSS_PUBLIC_KEY_BYTES);
  HRSS_marshal_public_key(
      const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(
          hrss_key_pair.hrss_public_key_marshaled.data())),
      &hrss_public_key);

  return hrss_key_pair;
}

crypto::tink::util::StatusOr<crypto::tink::pqc::Cecpq2KeyPair>
GenerateCecpq2Keypair(subtle::EllipticCurveType curve_type) {
  crypto::tink::pqc::Cecpq2KeyPair cecpq2_key_pair;

  // Generating a X25519 key pair
  cecpq2_key_pair.x25519_key_pair.priv.resize(X25519_PRIVATE_KEY_LEN);
  subtle::ResizeStringUninitialized(&(cecpq2_key_pair.x25519_key_pair.pub_x),
                                    X25519_PUBLIC_VALUE_LEN);
  X25519_keypair(const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(
                     cecpq2_key_pair.x25519_key_pair.pub_x.data())),
                 cecpq2_key_pair.x25519_key_pair.priv.data());

  // Generating a HRSS key pair
  util::SecretData generate_hrss_key_entropy =
      crypto::tink::subtle::Random::GetRandomKeyBytes(HRSS_GENERATE_KEY_BYTES);
  auto hrss_key_pair_or_status = GenerateHrssKeyPair(generate_hrss_key_entropy);
  cecpq2_key_pair.hrss_key_pair =
      std::move(hrss_key_pair_or_status.ValueOrDie());

  return cecpq2_key_pair;
}

}  // namespace pqc
}  // namespace tink
}  // namespace crypto
