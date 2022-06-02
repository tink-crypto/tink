// Copyright 2022 Google LLC
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

#ifndef TINK_HYBRID_INTERNAL_HPKE_UTIL_H_
#define TINK_HYBRID_INTERNAL_HPKE_UTIL_H_

namespace crypto {
namespace tink {
namespace internal {

// Values from https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
enum class HpkeKem {
  kUnknownKem = 0x0,
  kX25519HkdfSha256 = 0x20,
};

// Values from https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.
enum class HpkeKdf {
  kUnknownKdf = 0x0,
  kHkdfSha256 = 0x1,
};

// Values from https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
enum class HpkeAead {
  kUnknownAead = 0x0,
  kAes128Gcm = 0x1,
  kAes256Gcm = 0x2,
  kChaCha20Poly1305 = 0x3,
};

struct HpkeParams {
  HpkeKem kem;
  HpkeKdf kdf;
  HpkeAead aead;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_UTIL_H_
