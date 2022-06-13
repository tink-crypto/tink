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

#include "tink/experimental/pqcrypto/signature/subtle/sphincs_helper_pqclean.h"

#include <cstddef>
#include <memory>
#include <vector>

#include "absl/memory/memory.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-haraka-256s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-sha256-256s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-128s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-192s-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256f-simple/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-robust/api.h"
#include "third_party/pqclean/crypto_sign/sphincs-shake256-256s-simple/api.h"
}

#define NUM_VARIANTS 2
#define NUM_KEY_SIZES 3
#define NUM_SIG_LENGTHS 2

namespace crypto {
namespace tink {
namespace subtle {

class SphincsHaraka128FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka128FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA128FROBUST_CRYPTO_BYTES) {}

  ~SphincsHaraka128FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA128FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA128FROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA128FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka128SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka128SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA128SROBUST_CRYPTO_BYTES) {}

  ~SphincsHaraka128SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA128SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA128SROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA128SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka128FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka128FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA128FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsHaraka128FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA128FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA128FSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA128FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka128SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka128SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA128SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsHaraka128SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA128SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA128SSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA128SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka192FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka192FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA192FROBUST_CRYPTO_BYTES) {}

  ~SphincsHaraka192FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA192FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA192FROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA192FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka192SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka192SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA192SROBUST_CRYPTO_BYTES) {}

  ~SphincsHaraka192SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA192SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA192SROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA192SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka192FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka192FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA192FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsHaraka192FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA192FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA192FSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA192FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka192SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka192SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA192SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsHaraka192SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA192SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA192SSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA192SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka256FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka256FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA256FROBUST_CRYPTO_BYTES) {}

  ~SphincsHaraka256FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA256FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA256FROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA256FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka256SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka256SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA256SROBUST_CRYPTO_BYTES) {}

  ~SphincsHaraka256SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA256SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA256SROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA256SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka256FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka256FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA256FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsHaraka256FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA256FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA256FSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA256FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsHaraka256SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsHaraka256SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSHARAKA256SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsHaraka256SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA256SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSHARAKA256SSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSHARAKA256SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256128FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256128FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256128FROBUST_CRYPTO_BYTES) {}

  ~SphincsSHA256128FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256128FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256128FROBUST_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256128FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256128SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256128SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256128SROBUST_CRYPTO_BYTES) {}

  ~SphincsSHA256128SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256128SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256128SROBUST_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256128SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256128FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256128FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256128FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHA256128FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256128FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256128FSIMPLE_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256128FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256128SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256128SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256128SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHA256128SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256128SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256128SSIMPLE_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256128SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256192FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256192FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256192FROBUST_CRYPTO_BYTES) {}

  ~SphincsSHA256192FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256192FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256192FROBUST_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256192FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256192SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256192SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256192SROBUST_CRYPTO_BYTES) {}

  ~SphincsSHA256192SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256192SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256192SROBUST_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256192SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256192FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256192FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256192FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHA256192FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256192FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256192FSIMPLE_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256192FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256192SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256192SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256192SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHA256192SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256192SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256192SSIMPLE_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256192SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256256FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256256FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256256FROBUST_CRYPTO_BYTES) {}

  ~SphincsSHA256256FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256256FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256256FROBUST_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256256FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256256SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256256SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256256SROBUST_CRYPTO_BYTES) {}

  ~SphincsSHA256256SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256256SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256256SROBUST_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256256SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256256FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256256FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256256FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHA256256FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256256FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256256FSIMPLE_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256256FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHA256256SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHA256256SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHA256256SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHA256256SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256256SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHA256256SSIMPLE_crypto_sign_verify(sig, siglen,
                                                                   m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHA256256SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256128FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256128FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256128FROBUST_CRYPTO_BYTES) {}

  ~SphincsSHAKE256128FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256128FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256128FROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256128FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256128SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256128SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256128SROBUST_CRYPTO_BYTES) {}

  ~SphincsSHAKE256128SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256128SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256128SROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256128SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256128FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256128FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256128FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHAKE256128FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256128FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256128FSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256128FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256128SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256128SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256128SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHAKE256128SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256128SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256128SSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256128SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256192FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256192FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256192FROBUST_CRYPTO_BYTES) {}

  ~SphincsSHAKE256192FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256192FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256192FROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256192FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256192SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256192SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256192SROBUST_CRYPTO_BYTES) {}

  ~SphincsSHAKE256192SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256192SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256192SROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256192SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256192FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256192FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256192FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHAKE256192FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256192FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256192FSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256192FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256192SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256192SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256192SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHAKE256192SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256192SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256192SSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256192SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256256FRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256256FRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256256FROBUST_CRYPTO_BYTES) {}

  ~SphincsSHAKE256256FRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256256FROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256256FROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256256FROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256256SRobustPqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256256SRobustPqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256256SROBUST_CRYPTO_BYTES) {}

  ~SphincsSHAKE256256SRobustPqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256256SROBUST_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256256SROBUST_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256256SROBUST_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256256FSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256256FSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256256FSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHAKE256256FSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256256FSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256256FSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256256FSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

class SphincsSHAKE256256SSimplePqclean : public SphincsHelperPqclean {
 public:
  SphincsSHAKE256256SSimplePqclean()
      : SphincsHelperPqclean(
            PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_PUBLICKEYBYTES,
            PQCLEAN_SPHINCSSHAKE256256SSIMPLE_CRYPTO_BYTES) {}

  ~SphincsSHAKE256256SSimplePqclean() override = default;

  int Sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
           const uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256256SSIMPLE_crypto_sign_signature(
        sig, siglen, m, mlen, sk);
  }

  int Verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
             const uint8_t *pk) const override {
    return PQCLEAN_SPHINCSSHAKE256256SSIMPLE_crypto_sign_verify(
        sig, siglen, m, mlen, pk);
  }

  int Keygen(uint8_t *pk, uint8_t *sk) const override {
    return PQCLEAN_SPHINCSSHAKE256256SSIMPLE_crypto_sign_keypair(pk, sk);
  }
};

std::vector<std::unique_ptr<SphincsHelperPqclean>>
GetSphincsPqcleanHelperArray() {
  std::vector<std::unique_ptr<SphincsHelperPqclean>> sphincs_helper_pqclean;

  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka128FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka128SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka128FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka128SSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka192FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka192SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka192FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka192SSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka256FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka256SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka256FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsHaraka256SSimplePqclean>());

  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256128FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256128SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256128FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256128SSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256192FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256192SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256192FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256192SSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256256FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256256SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256256FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHA256256SSimplePqclean>());

  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256128FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256128SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256128FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256128SSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256192FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256192SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256192FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256192SSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256256FRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256256SRobustPqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256256FSimplePqclean>());
  sphincs_helper_pqclean.push_back(
      absl::make_unique<SphincsSHAKE256256SSimplePqclean>());

  return sphincs_helper_pqclean;
}

const SphincsHelperPqclean &GetSphincsHelperPqclean(int hash_type, int variant,
                                                    int key_size,
                                                    int signature_length) {
  static std::vector<std::unique_ptr<SphincsHelperPqclean>>
      *sphincs_helper_pqclean = new std::vector(GetSphincsPqcleanHelperArray());

  return *sphincs_helper_pqclean->at(
      hash_type * NUM_VARIANTS * NUM_KEY_SIZES * NUM_SIG_LENGTHS +
      key_size * NUM_VARIANTS * NUM_SIG_LENGTHS + variant * NUM_SIG_LENGTHS +
      signature_length);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
