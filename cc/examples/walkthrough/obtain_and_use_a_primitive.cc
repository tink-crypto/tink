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

#include "walkthrough/obtain_and_use_a_primitive.h"

// [START tink_walkthrough_obtain_and_use_a_primitive]
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"

namespace tink_walkthrough {

using ::crypto::tink::Aead;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::util::StatusOr;

// AEAD encrypts `plaintext` with `associated_data` and the primary key in
// `keyset_handle`.
//
// Prerequisites for this example:
//  - Register AEAD implementations of Tink.
//  - Create a keyset and get a handle to it.
StatusOr<std::string> AeadEncrypt(const KeysetHandle& keyset_handle,
                                  absl::string_view palintext,
                                  absl::string_view associated_data) {
  // To facilitate key rotation, GetPrimitive returns an Aead primitive that
  // "wraps" multiple Aead primitives in the keyset. When encrypting it uses the
  // primary key.
  StatusOr<std::unique_ptr<Aead>> aead = keyset_handle.GetPrimitive<Aead>();
  if (!aead.ok()) {
    return aead.status();
  }
  return (*aead)->Encrypt(palintext, associated_data);
}

// AEAD decrypts `ciphertext` with `associated_data` and the correct key in
// `keyset_handle`.
//
// Prerequisites for this example:
//  - Register AEAD implementations of Tink.
//  - Create a keyset and get a handle to it.
StatusOr<std::string> AeadDecrypt(const KeysetHandle& keyset_handle,
                                  absl::string_view ciphertext,
                                  absl::string_view associated_data) {
  // To facilitate key rotation, GetPrimitive returns an Aead primitive that
  // "wraps" multiple Aead primitives in the keyset. When decrypting it uses the
  // key that was used to encrypt using the key ID contained in the ciphertext.
  StatusOr<std::unique_ptr<Aead>> aead = keyset_handle.GetPrimitive<Aead>();
  if (!aead.ok()) {
    return aead.status();
  }
  return (*aead)->Decrypt(ciphertext, associated_data);
}

}  // namespace tink_walkthrough
// [END tink_walkthrough_obtain_and_use_a_primitive]
