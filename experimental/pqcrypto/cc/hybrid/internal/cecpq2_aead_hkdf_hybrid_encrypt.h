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

#ifndef THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_INTERNAL_CECPQ2_AEAD_HKDF_HYBRID_ENCRYPT_H_
#define THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_INTERNAL_CECPQ2_AEAD_HKDF_HYBRID_ENCRYPT_H_

#include <memory>

#include "tink/hybrid_encrypt.h"
#include "tink/util/statusor.h"
#include "pqcrypto/cc/hybrid/cecpq2_aead_hkdf_dem_helper.h"
#include "pqcrypto/cc/hybrid/internal/cecpq2_aead_hkdf_hybrid_decrypt.h"
#include "pqcrypto/cc/subtle/cecpq2_hkdf_sender_kem_boringssl.h"
#include "pqcrypto/cc/subtle/cecpq2_subtle_boringssl_util.h"

namespace crypto {
namespace tink {

// CECPQ2 encryption with HKDF-KEM (key encapsulation mechanism) and
// AEAD-DEM (data encapsulation mechanism)
class Cecpq2AeadHkdfHybridEncrypt : public HybridEncrypt {
 public:
  // Returns an HybridEncrypt-primitive that uses the key material
  // given in 'recipient_key'
  static crypto::tink::util::StatusOr<std::unique_ptr<HybridEncrypt>> New(
      const Cecpq2AeadHkdfPublicKeyInternal& recipient_key);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view context_info) const override;

 private:
  Cecpq2AeadHkdfHybridEncrypt(
      const Cecpq2AeadHkdfPublicKeyInternal& recipient_key,
      std::unique_ptr<const subtle::Cecpq2HkdfSenderKemBoringSsl> sender_kem,
      std::unique_ptr<const Cecpq2AeadHkdfDemHelper> dem_helper)
      : recipient_key_(recipient_key),
        sender_kem_(std::move(sender_kem)),
        dem_helper_(std::move(dem_helper)) {}

  Cecpq2AeadHkdfPublicKeyInternal recipient_key_;
  std::unique_ptr<const subtle::Cecpq2HkdfSenderKemBoringSsl> sender_kem_;
  std::unique_ptr<const Cecpq2AeadHkdfDemHelper> dem_helper_;
};

}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_INTERNAL_CECPQ2_AEAD_HKDF_HYBRID_ENCRYPT_H_
