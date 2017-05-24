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

#include "cc/hybrid_encrypt.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// ECIES encryption with HKDF-KEM (key encapsulation mechanism) and
// AEAD-DEM (data encapsulation mechanism).
class EciesAeadHkdfHybridEncrypt : public HybridEncrypt {
 public:
  // Returns an HybridEncrypt-primitive that uses the key material
  // given in 'recipient_key'.
  static util::StatusOr<std::unique_ptr<HybridEncrypt>> New(
      const google::crypto::tink::EciesAeadHkdfPublicKey& recipient_key);

  util::StatusOr<std::string> Encrypt(
      google::protobuf::StringPiece plaintext,
      google::protobuf::StringPiece context_info) const override;

  virtual ~EciesAeadHkdfHybridEncrypt() {}

 private:
  EciesAeadHkdfHybridEncrypt(
      const google::crypto::tink::EciesAeadHkdfPublicKey& recipient_key)
      : recipient_key_(recipient_key) {}

  google::crypto::tink::EciesAeadHkdfPublicKey recipient_key_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_AEAD_HKDF_HYBRID_ENCRYPT_H_
