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

#ifndef TINK_DETERMINISTIC_AEAD_H_
#define TINK_DETERMINISTIC_AEAD_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// The interface for deterministic authenticated encryption with associated
// data.
// TODO(bleichen): Copy the interface from Java.
//   Check the properties:
//   - authenticated
//   - secure in multi-user setting
//   - thread safe/copy safe
// References:
// https://eprint.iacr.org/2016/1124.pdf
class DeterministicAead {
 public:
  // Encrypts 'plaintext' with 'associated_data' as associated data
  // deterministically, and returns the resulting ciphertext.
  // The ciphertext allows for checking authenticity and integrity
  // of the associated data, but does not guarantee its secrecy.
  virtual crypto::tink::util::StatusOr<std::string> EncryptDeterministically(
      absl::string_view plaintext, absl::string_view associated_data) const = 0;

  // Decrypts 'ciphertext' with 'associated_data' as associated data,
  // and returns the resulting plaintext.
  // The decryption verifies the authenticity and integrity
  // of the associated data, but there are no guarantees wrt. secrecy
  // of that data.
  virtual crypto::tink::util::StatusOr<std::string> DecryptDeterministically(
      absl::string_view ciphertext,
      absl::string_view associated_data) const = 0;

  virtual ~DeterministicAead() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_DETERMINISTIC_AEAD_H_
