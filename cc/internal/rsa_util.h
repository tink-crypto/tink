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
#ifndef TINK_INTERNAL_RSA_UTIL_H_
#define TINK_INTERNAL_RSA_UTIL_H_

#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

struct RsaPublicKey {
  // Modulus.
  // Unsigned big integer in bigendian representation.
  std::string n;
  // Public exponent.
  // Unsigned big integer in bigendian representation.
  std::string e;
};

// Parameters of RSA SSA (Signature Schemes with Appendix) using  PSS
// (Probabilistic Signature Scheme) encoding (see
// https://tools.ietf.org/html/rfc8017#section-8.1).
struct RsaSsaPssParams {
  // Hash function used in computing hash of the signing message
  // (see https://tools.ietf.org/html/rfc8017#section-9.1.1).
  subtle::HashType sig_hash;
  // Hash function used in MGF1 (a mask generation function based on a
  // hash function) (see https://tools.ietf.org/html/rfc8017#appendix-B.2.1).
  subtle::HashType mgf1_hash;
  // Salt length (see https://tools.ietf.org/html/rfc8017#section-9.1.1)
  int salt_length;
};

// Parameters of RSA SSA (Signature Schemes with Appendix) using PKCS1
// (Probabilistic Signature Scheme) encoding (see
// https://tools.ietf.org/html/rfc8017#section-8.2).
struct RsaSsaPkcs1Params {
  // Hash function used in computing hash of the signing message
  // (see https://tools.ietf.org/html/rfc8017#section-9.2).
  subtle::HashType hash_type;
};

// RSA private key representation.
struct RsaPrivateKey {
  // Modulus.
  std::string n;
  // Public exponent.
  std::string e;
  // Private exponent.
  // Unsigned big integer in bigendian representation.
  util::SecretData d;

  // The prime factor p of n.
  // Unsigned big integer in bigendian representation.
  util::SecretData p;
  // The prime factor q of n.
  // Unsigned big integer in bigendian representation.
  util::SecretData q;
  // d mod (p - 1).
  util::SecretData dp;
  // d mod (q - 1).
  // Unsigned big integer in bigendian representation.
  util::SecretData dq;
  // Chinese Remainder Theorem coefficient q^(-1) mod p.
  // Unsigned big integer in bigendian representation.
  util::SecretData crt;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_RSA_UTIL_H_
