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

#ifndef THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_CECPQ2_HYBRID_KEY_TEMPLATES_H_
#define THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_CECPQ2_HYBRID_KEY_TEMPLATES_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Pre-generated KeyTemplate for hybrid key types. One can use these templates
// to generate a new KeysetHandle object with fresh keys.
// To generate a new keyset that contains a single Cecpq2AeadHkdfPrivateKey,
// one can do:
//
//   auto status = Cecpq2HybridConfig::Register();
//   if (!status.ok()) { /* fail with error */ }
//   auto handle_result = KeysetHandle::GenerateNew(
//        Cecpq2HybridKeyTemplates::Cecpq2P256HkdfHmacSha256Aes128Gcm());
//   if (!handle_result.ok()) { /* fail with error */ }
//   auto keyset_handle = std::move(handle_result.ValueOrDie());

// Returns a KeyTemplate that generates new instances of
// Cecpq2AeadHkdfPrivateKey with the following parameters:
//   - KEM: CECPQ2
//   - DEM: AES256-GCM
//   - KDF: HKDF-HMAC-SHA256 with an empty salt
//   - EC Point Format: Compressed
//   - OutputPrefixType: TINK
const google::crypto::tink::KeyTemplate&
Cecpq2HybridKeyTemplateX25519HkdfHmacSha256Aes256Gcm();

// Returns a KeyTemplate that generates new instances of
// Cecpq2AeadHkdfPrivateKey with the following parameters:
//   - KEM: CECPQ2
//   - DEM: XChaCha20-Poly1305 with the following parameters:
//          * XChaCha20 key size: 32 bytes
//          * IV size: 24 bytes
//   - KDF: HKDF-HMAC-SHA256 with an empty salt
//   - EC Point Format: Compressed
//   - OutputPrefixType: TINK
const google::crypto::tink::KeyTemplate&
Cecpq2HybridKeyTemplateX25519HkdfHmacSha256XChaCha20Poly1305();

// Returns a KeyTemplate that generates new instances of
// Cecpq2AeadHkdfPrivateKey with the following parameters:
//   - KEM: CECPQ2
//   - DEM: AES256-SIV (Deterministic Aead)
//   - KDF: HKDF-HMAC-SHA256 with an empty salt
//   - EC Point Format: Compressed
//   - OutputPrefixType: TINK
const google::crypto::tink::KeyTemplate&
Cecpq2HybridKeyTemplateX25519HkdfHmacSha256DeterministicAesSiv();

}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_CECPQ2_HYBRID_KEY_TEMPLATES_H_
