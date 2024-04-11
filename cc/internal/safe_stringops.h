// Copyright 2024 Google LLC
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

#ifndef TINK_INTERNAL_SAFE_STRINGOPS_H_
#define TINK_INTERNAL_SAFE_STRINGOPS_H_

#include <cstring>

#include "tink/internal/call_with_core_dump_protection.h"
#include "openssl/crypto.h"

namespace crypto {
namespace tink {
namespace internal {

// Equivalents of regular memcpy/memmove, which do not leak contents of the
// arguments in the core dump.

inline void* SafeMemCopy(void* dst, const void* src, size_t n) {
  return CallWithCoreDumpProtection(
      [dst, src, n]() { return memcpy(dst, src, n); });
}

inline void* SafeMemMove(void* dst, const void* src, size_t n) {
  return CallWithCoreDumpProtection(
      [dst, src, n]() { return memmove(dst, src, n); });
}

// Test equality of two memory areas.
// Not only protects from leaking any info about the contents in the core dump,
// but also is safe for crypto material (const time).

inline int SafeCryptoMemEquals(const void* s1, const void* s2, size_t n) {
  return CallWithCoreDumpProtection(
      [s1, s2, n]() { return CRYPTO_memcmp(s1, s2, n) == 0; });
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SAFE_STRINGOPS_H_
