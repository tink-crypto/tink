// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_SUBTLE_HYBRID_TEST_UTIL_H_
#define TINK_SUBTLE_HYBRID_TEST_UTIL_H_

#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/util/status.h"

// Encrypt with the encrypter, then decrypt with the decrypter. Returns OK if
// the resulting decryption is equal to the plaintext. Errors are propagated.

namespace crypto {
namespace tink {

crypto::tink::util::Status HybridEncryptThenDecrypt(
    HybridEncrypt* encrypter, HybridDecrypt* decrypter,
    absl::string_view plaintext, absl::string_view context_info);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_HYBRID_TEST_UTIL_H_
