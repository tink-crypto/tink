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
#ifndef TINK_SUBTLE_AEAD_TEST_UTIL_H_
#define TINK_SUBTLE_AEAD_TEST_UTIL_H_

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/cord_aead.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

// Encrypt, then decrypt. Any error will be propagated to the caller. Returns OK
// if the resulting decryption is equal to the plaintext.
crypto::tink::util::Status EncryptThenDecrypt(const Aead& encrypter,
                                              const Aead& decrypter,
                                              absl::string_view message,
                                              absl::string_view aad);

// Encrypt, then decrypt. Any error will be propagated to the caller. Returns OK
// if the resulting decryption is equal to the plaintext.
crypto::tink::util::Status EncryptThenDecrypt(const CordAead& encrypter,
                                              const CordAead& decrypter,
                                              absl::string_view message,
                                              absl::string_view aad);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AEAD_TEST_UTIL_H_
