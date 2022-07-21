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

#ifndef TINK_HYBRID_ECIES_AEAD_HKDF_HYBRID_ENCRYPT_H_
#define TINK_HYBRID_ECIES_AEAD_HKDF_HYBRID_ENCRYPT_H_

#include <memory>
#include <string>
#include <utility>

#include "tink/hybrid/ecies_aead_hkdf_dem_helper.h"
#include "tink/hybrid_encrypt.h"
#include "tink/subtle/ecies_hkdf_sender_kem_boringssl.h"
#include "tink/util/statusor.h"
#include "proto/ecies_aead_hkdf.pb.h"

namespace crypto {
namespace tink {

// ECIES encryption with HKDF-KEM (key encapsulation mechanism) and
// AEAD-DEM (data encapsulation mechanism).
class EciesAeadHkdfHybridEncrypt : public HybridEncrypt {
 public:
  // Returns an HybridEncrypt-primitive that uses the key material
  // given in 'recipient_key'.
  static crypto::tink::util::StatusOr<std::unique_ptr<HybridEncrypt>> New(
      const google::crypto::tink::EciesAeadHkdfPublicKey& recipient_key);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view context_info) const override;

 private:
  EciesAeadHkdfHybridEncrypt(
      const google::crypto::tink::EciesAeadHkdfPublicKey& recipient_key,
      std::unique_ptr<const subtle::EciesHkdfSenderKemBoringSsl> sender_kem,
      std::unique_ptr<const EciesAeadHkdfDemHelper> dem_helper)
      : recipient_key_(recipient_key), sender_kem_(std::move(sender_kem)),
        dem_helper_(std::move(dem_helper)) {}

  google::crypto::tink::EciesAeadHkdfPublicKey recipient_key_;
  std::unique_ptr<const subtle::EciesHkdfSenderKemBoringSsl> sender_kem_;
  std::unique_ptr<const EciesAeadHkdfDemHelper> dem_helper_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_AEAD_HKDF_HYBRID_ENCRYPT_H_
