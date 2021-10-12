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
#include "tink/subtle/aead_test_util.h"

#include <string>

#include "tink/subtle/test_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::StatusOr;

crypto::tink::util::Status EncryptThenDecrypt(const Aead& encrypter,
                                              const Aead& decrypter,
                                              absl::string_view message,
                                              absl::string_view aad) {
  StatusOr<std::string> encryption_or = encrypter.Encrypt(message, aad);
  if (!encryption_or.status().ok()) return encryption_or.status();
  StatusOr<std::string> decryption_or =
      decrypter.Decrypt(encryption_or.ValueOrDie(), aad);
  if (!decryption_or.status().ok()) return decryption_or.status();
  if (decryption_or.ValueOrDie() != message) {
    return crypto::tink::util::Status(absl::StatusCode::kInternal,
                                      "Message/Decryption mismatch");
  }
  return util::OkStatus();
}

crypto::tink::util::Status EncryptThenDecrypt(const CordAead& encrypter,
                                              const CordAead& decrypter,
                                              absl::string_view message,
                                              absl::string_view aad) {
  absl::Cord message_cord = absl::Cord(message);
  absl::Cord aad_cord = absl::Cord(aad);
  StatusOr<absl::Cord> encryption_or =
      encrypter.Encrypt(message_cord, aad_cord);
  if (!encryption_or.status().ok()) return encryption_or.status();
  StatusOr<absl::Cord> decryption_or =
      decrypter.Decrypt(encryption_or.ValueOrDie(), aad_cord);
  if (!decryption_or.status().ok()) return decryption_or.status();
  if (decryption_or.ValueOrDie() != message) {
    return crypto::tink::util::Status(absl::StatusCode::kInternal,
                                      "Message/Decryption mismatch");
  }
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
