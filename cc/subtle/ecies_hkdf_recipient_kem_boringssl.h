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

#ifndef TINK_SUBTLE_ECIES_HKDF_RECIPIENT_KEM_BORINGSSL_H_
#define TINK_SUBTLE_ECIES_HKDF_RECIPIENT_KEM_BORINGSSL_H_

#include "absl/strings/string_view.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"
#include "openssl/ec.h"

namespace crypto {
namespace tink {
namespace subtle {

// HKDF-based KEM (key encapsulation mechanism) for ECIES recipient,
// using Boring SSL for the underlying cryptographic operations.
class EciesHkdfRecipientKemBoringSsl {
 public:
  // Constructs a recipient KEM for the specified curve and recipient's
  // private key, which must be a big-endian byte array.
  static
  crypto::tink::util::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
      New(EllipticCurveType curve, const std::string& priv_key);

  // Computes the ecdh's shared secret from our private key and peer's encoded
  // public key, then uses hkdf to derive the symmetric key from the shared
  // secret, hkdf info and hkdf salt.
  crypto::tink::util::StatusOr<std::string> GenerateKey(
      absl::string_view kem_bytes,
      HashType hash,
      absl::string_view hkdf_salt,
      absl::string_view hkdf_info,
      uint32_t key_size_in_bytes,
      EcPointFormat point_format) const;

 private:
  EciesHkdfRecipientKemBoringSsl(
      EllipticCurveType curve,
      const std::string& priv_key_value);

  EllipticCurveType curve_;
  std::string priv_key_value_;
  bssl::UniquePtr<EC_GROUP> ec_group_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ECIES_HKDF_RECIPIENT_KEM_BORINGSSL_H_
