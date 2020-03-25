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

#ifndef TINK_SUBTLE_IND_CPA_CIPHER_H_
#define TINK_SUBTLE_IND_CPA_CIPHER_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

///////////////////////////////////////////////////////////////////////////////
// This interface for symmetric key ciphers that are indistinguishable against
// chosen-plaintext attacks. Said primitives do not provide authentication,
// thus should not be used directly, but only to construct safer primitives
// such as Aead.
class IndCpaCipher {
 public:
  // Encrypts 'plaintext'. The resulting ciphertext is indistinguishable under
  // chosen-plaintext attack. However, it does not have integrity protection.
  virtual crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext) const = 0;

  // Decrypts 'ciphertext' and returns the resulting plaintext.
  virtual crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext) const = 0;

  virtual ~IndCpaCipher() {}
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_IND_CPA_CIPHER_H_
