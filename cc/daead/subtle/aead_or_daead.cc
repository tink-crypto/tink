// Copyright 2020 Google LLC
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

#include "tink/daead/subtle/aead_or_daead.h"

#include <string>
#include <utility>

#include "absl/functional/bind_front.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// Functor implementing Encryption of a given plaintext.
struct EncryptFunctor {
  crypto::tink::util::StatusOr<std::string> operator()(
      absl::string_view plaintext, absl::string_view associated_data,
      const std::unique_ptr<const Aead>& aead_primitive) {
    return aead_primitive->Encrypt(plaintext, associated_data);
  }
  crypto::tink::util::StatusOr<std::string> operator()(
      absl::string_view plaintext, absl::string_view associated_data,
      const std::unique_ptr<const DeterministicAead>& aead_primitive) {
    return aead_primitive->EncryptDeterministically(plaintext, associated_data);
  }
};

// Functor implementing Decryption of a given ciphertext.
struct DecryptFunctor {
  crypto::tink::util::StatusOr<std::string> operator()(
      absl::string_view ciphertext, absl::string_view associated_data,
      const std::unique_ptr<const Aead>& aead_primitive) {
    return aead_primitive->Decrypt(ciphertext, associated_data);
  }
  crypto::tink::util::StatusOr<std::string> operator()(
      absl::string_view ciphertext, absl::string_view associated_data,
      const std::unique_ptr<const DeterministicAead>& aead_primitive) {
    return aead_primitive->DecryptDeterministically(ciphertext,
                                                    associated_data);
  }
};
}  // namespace

crypto::tink::util::StatusOr<std::string> AeadOrDaead::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  return absl::visit(
      absl::bind_front(EncryptFunctor(), plaintext, associated_data),
      primitive_variant_);
}

crypto::tink::util::StatusOr<std::string> AeadOrDaead::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  return absl::visit(
      absl::bind_front(DecryptFunctor(), ciphertext, associated_data),
      primitive_variant_);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
