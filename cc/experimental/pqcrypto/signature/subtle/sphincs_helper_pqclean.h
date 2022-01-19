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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_SPHINCS_HELPER_PQCLEAN_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_SPHINCS_HELPER_PQCLEAN_H_

#include <memory>
#include <vector>

#include "absl/base/attributes.h"

namespace crypto {
namespace tink {
namespace subtle {

class SphincsHelperPqclean {
 public:
  SphincsHelperPqclean(int public_key_size, int signature_length)
      : public_key_size_(public_key_size),
        signature_length_(signature_length) {}

  SphincsHelperPqclean(const SphincsHelperPqclean &other) = delete;
  SphincsHelperPqclean &operator=(const SphincsHelperPqclean &other) = delete;
  virtual ~SphincsHelperPqclean() {}

  // Arguments:
  //   sig - output signature (allocated buffer of size at least
  //   GetSignatureLength()); siglen - output length of signature; m - message
  //   to be signed; mlen - length of message; sk - bit-packed secret key.
  // Computes signature. Returns 0 (success).
  virtual ABSL_MUST_USE_RESULT int Sign(uint8_t *sig, size_t *siglen,
                                        const uint8_t *m, size_t mlen,
                                        const uint8_t *sk) const = 0;

  // Arguments:
  //   sig - input signature; siglen - length of signature;
  //   m - input message; mlen - length of message; pk - bit-packed public key.
  // Verifies the signature. Returns 0 (success).
  virtual ABSL_MUST_USE_RESULT int Verify(const uint8_t *sig, size_t siglen,
                                          const uint8_t *m, size_t mlen,
                                          const uint8_t *pk) const = 0;

  // Arguments:
  //   pk - output public key (allocated buffer of the corresponding public key
  //   size); sk - output private key (allocated buffer of the corresponding
  //   private key size)
  // Gnerates the key pair. Returns 0 (success).
  virtual ABSL_MUST_USE_RESULT int Keygen(uint8_t *pk, uint8_t *sk) const = 0;

  int GetPublicKeySize() const { return public_key_size_; }
  int GetSignatureLength() const { return signature_length_; }

 private:
  int public_key_size_;
  int signature_length_;
};

// Returns a pointer to the corresponding SphincsHelperPqclean derived class.
// Will be used for the key generation, signing and verifing.
const SphincsHelperPqclean &GetSphincsHelperPqclean(int hash_type, int variant,
                                                    int key_size,
                                                    int signature_length);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SUBTLE_SPHINCS_HELPER_PQCLEAN_H_
