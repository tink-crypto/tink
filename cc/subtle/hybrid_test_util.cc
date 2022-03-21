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

#include "tink/subtle/hybrid_test_util.h"

#include "absl/status/status.h"

namespace crypto {
namespace tink {

crypto::tink::util::Status HybridEncryptThenDecrypt(
    HybridEncrypt* encrypter, HybridDecrypt* decrypter,
    absl::string_view plaintext, absl::string_view context_info) {
  auto ciphertext = encrypter->Encrypt(plaintext, context_info);
  if (!ciphertext.ok()) return ciphertext.status();

  auto decryption = decrypter->Decrypt(ciphertext.value(), context_info);
  if (!decryption.ok()) return decryption.status();

  if (decryption.value() != plaintext) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      "decryption and encryption differ");
  }
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
