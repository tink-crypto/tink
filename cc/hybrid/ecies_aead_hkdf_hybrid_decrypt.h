// Copyright 2017 Google Inc.
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

#ifndef TINK_HYBRID_ECIES_AEAD_HKDF_HYBRID_DECRYPT_H_
#define TINK_HYBRID_ECIES_AEAD_HKDF_HYBRID_DECRYPT_H_

#include <memory>
#include <string>
#include <utility>

#include "tink/hybrid/ecies_aead_hkdf_dem_helper.h"
#include "tink/hybrid_decrypt.h"
#include "tink/subtle/ecies_hkdf_recipient_kem_boringssl.h"
#include "tink/util/statusor.h"
#include "proto/ecies_aead_hkdf.pb.h"

namespace crypto {
namespace tink {

// ECIES decryption with HKDF-KEM (key encapsulation mechanism) and
// AEAD-DEM (data encapsulation mechanism).
class EciesAeadHkdfHybridDecrypt : public HybridDecrypt {
 public:
  // Returns an HybridDecrypt-primitive that uses the key material
  // given in 'recipient_key'.
  static crypto::tink::util::StatusOr<std::unique_ptr<HybridDecrypt>> New(
      const google::crypto::tink::EciesAeadHkdfPrivateKey& recipient_key);

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view context_info) const override;

 private:
  EciesAeadHkdfHybridDecrypt(
      google::crypto::tink::EciesAeadHkdfParams recipient_key_params,
      std::unique_ptr<const subtle::EciesHkdfRecipientKemBoringSsl> kem,
      std::unique_ptr<const EciesAeadHkdfDemHelper> dem_helper)
      : recipient_key_params_(std::move(recipient_key_params)),
        recipient_kem_(std::move(kem)),
        dem_helper_(std::move(dem_helper)) {}

  google::crypto::tink::EciesAeadHkdfParams recipient_key_params_;
  std::unique_ptr<const subtle::EciesHkdfRecipientKemBoringSsl> recipient_kem_;
  std::unique_ptr<const EciesAeadHkdfDemHelper> dem_helper_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_AEAD_HKDF_HYBRID_DECRYPT_H_
