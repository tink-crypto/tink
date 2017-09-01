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

#include "cc/hybrid_decrypt.h"
#include "cc/hybrid/ecies_aead_hkdf_dem_helper.h"
#include "cc/subtle/ecies_hkdf_recipient_kem_boringssl.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

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
      google::protobuf::StringPiece ciphertext,
      google::protobuf::StringPiece context_info) const override;

  virtual ~EciesAeadHkdfHybridDecrypt() {}

 private:
  static crypto::tink::util::Status Validate(
      const google::crypto::tink::EciesAeadHkdfPrivateKey& key);

  EciesAeadHkdfHybridDecrypt(
      const google::crypto::tink::EciesAeadHkdfPrivateKey& recipient_key,
      std::unique_ptr<EciesHkdfRecipientKemBoringSsl> recipient_kem,
      std::unique_ptr<EciesAeadHkdfDemHelper> dem_helper)
      : recipient_key_(recipient_key), recipient_kem_(std::move(recipient_kem)),
        dem_helper_(std::move(dem_helper)) {}

  google::crypto::tink::EciesAeadHkdfPrivateKey recipient_key_;
  std::unique_ptr<EciesHkdfRecipientKemBoringSsl> recipient_kem_;
  std::unique_ptr<EciesAeadHkdfDemHelper> dem_helper_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_AEAD_HKDF_HYBRID_DECRYPT_H_
