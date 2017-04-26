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

#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/common.pb.h"

using google::cloud::crypto::tink::HashType;
using google::cloud::crypto::tink::EllipticCurveType;
using google::cloud::crypto::tink::EcPointFormat;
using google::protobuf::StringPiece;

namespace cloud {
namespace crypto {
namespace tink {

class EciesHkdfRecipientKemBoringSsl {
 public:
  // Constructor based on elliptic curve type and private key. The private key
  // is big-endian byte array.
  explicit EciesHkdfRecipientKemBoringSsl(EllipticCurveType curve,
                                          const std::string& priv_key);
  // Computes the ecdh's shared secret from our private key and peer's encoded
  // public key, then uses hkdf to derive the symmetric key from the shared
  // secret, hkdf info and hkdf salt.
  util::StatusOr<std::string> GenerateKey(StringPiece kem_bytes, HashType hash,
                                          StringPiece hkdf_salt,
                                          StringPiece hkdf_info,
                                          int key_size_in_bytes,
                                          EcPointFormat point_format) const;

 private:
  EllipticCurveType curve_;
  std::string priv_;
};

}  // namespace tink
}  // namespace crypto
}  // namespace cloud

#endif  // TINK_SUBTLE_ECIES_HKDF_RECIPIENT_KEM_BORINGSSL_H_
