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
#include "pqcrypto/cc/subtle/hrss_boringssl.h"

#include "openssl/hrss.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {

util::StatusOr<std::unique_ptr<HrssKem>> HrssKem::New() {
  auto hrss_kem = absl::WrapUnique(new HrssKem());
  // creating a random seed for the key generation procedure:
  util::SecretData seed =
      crypto::tink::subtle::Random::GetRandomKeyBytes(HRSS_GENERATE_KEY_BYTES);

  HRSS_generate_key(&(hrss_kem->pub_), hrss_kem->priv_.get(),
                    reinterpret_cast<const uint8_t *>(seed.data()));

  return hrss_kem;
}

crypto::tink::util::StatusOr<HrssKem::KemCiphertextSharedKey>
HrssKem::Encapsulate(const absl::string_view in_plaintext) {
  if (in_plaintext.length() != HRSS_ENCAP_BYTES) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrCat("invalid plaintext size (", HRSS_ENCAP_BYTES,
                     " bytes needed)"));
  }

  HrssKem::KemCiphertextSharedKey kem_ct_shared_key;
  subtle::ResizeStringUninitialized(&(kem_ct_shared_key.kem_ciphertext),
                                    HRSS_CIPHERTEXT_BYTES);

  HRSS_encap(
      reinterpret_cast<uint8_t *>(&(kem_ct_shared_key.kem_ciphertext[0])),
      reinterpret_cast<uint8_t *>(&(kem_ct_shared_key.kem_shared_key[0])),
      &pub_, reinterpret_cast<const uint8_t *>(in_plaintext.data()));

  return kem_ct_shared_key;
}

crypto::tink::util::StatusOr<util::SecretData> HrssKem::Decapsulate(
    const absl::string_view in_ciphertext) {
  if (in_ciphertext.length() != HRSS_CIPHERTEXT_BYTES) {
    return crypto::tink::util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrCat("invalid ciphertext size (", HRSS_CIPHERTEXT_BYTES,
                     " bytes needed)"));
  }

  util::SecretData out_shared_key(HRSS_KEY_BYTES, 0);
  HRSS_decap(reinterpret_cast<uint8_t *>(&(out_shared_key[0])), priv_.get(),
             reinterpret_cast<const uint8_t *>(&(in_ciphertext[0])),
             HRSS_CIPHERTEXT_BYTES);

  return out_shared_key;
}

}  // namespace tink
}  // namespace crypto
