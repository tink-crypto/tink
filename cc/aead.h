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

#ifndef TINK_AEAD_H_
#define TINK_AEAD_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// The interface for authenticated encryption with associated data.
// Implementations of this interface are secure against adaptive
// chosen ciphertext attacks.  Encryption with associated data ensures
// authenticity and integrity of that data, but not its secrecy.
// (see RFC 5116, https://tools.ietf.org/html/rfc5116)
//
// Implementations are expected to be thread safe.
class Aead {
 public:
  // Encrypts 'plaintext' with 'associated_data' as associated data,
  // and returns the resulting ciphertext.
  // The ciphertext allows for checking authenticity and integrity
  // of the associated data, but does not guarantee its secrecy.
  virtual crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext, absl::string_view associated_data) const = 0;

  // Decrypts 'ciphertext' with 'associated_data' as associated data,
  // and returns the resulting plaintext.
  // The decryption verifies the authenticity and integrity
  // of the associated data, but there are no guarantees wrt. secrecy
  // of that data.
  virtual crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const = 0;

  virtual ~Aead() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_H_
