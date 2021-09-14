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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SPHINCS_KEY_TEMPLATE_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SPHINCS_KEY_TEMPLATE_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Pre-generated KeyTemplates for Sphincs key type.

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_128_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_128_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_128_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_128_S_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_192_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_192_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_192_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_192_S_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_256_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_256_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_256_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: HARAKA
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Haraka_256_S_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_128_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_128_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_128_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_128_S_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_192_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_192_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_192_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_192_S_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_256_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_256_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_256_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHA256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Sha256_256_S_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_128_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_128_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_128_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 64
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_128_S_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_192_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_192_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_192_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 96
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_192_S_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_256_F_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: FAST SIGNING
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_256_F_Simple_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: ROBUST
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_256_S_Robust_KeyTemplate();

// Returns a KeyTemplate that generates new instances of
// SphincsPrivateKey with the following parameters:
//   - HASH: SHAKE256
//   - VARIANT: SIMPLE
//   - SIGNING TYPE: SMALL SIGNATURE
//   - PRIVATE KEY SIZE: 128
const google::crypto::tink::KeyTemplate&
Sphincs_Shake256_256_S_Simple_KeyTemplate();

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_SPHINCS_KEY_TEMPLATE_H_
