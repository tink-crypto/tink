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

#ifndef TINK_DAEAD_SUBTLE_AEAD_OR_DAEAD_H_
#define TINK_DAEAD_SUBTLE_AEAD_OR_DAEAD_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/types/variant.h"
#include "tink/aead.h"
#include "tink/deterministic_aead.h"

namespace crypto {
namespace tink {
namespace subtle {

// This wrapper class abstracts away the differences between Deterministic Aead
// and non-determinstic Aead primitives. This can be useful for building
// higher-level functionality in which either of these primitives can be used.
class AeadOrDaead {
 public:
  explicit AeadOrDaead(std::unique_ptr<Aead> aead_primitive)
      : primitive_variant_(std::move(aead_primitive)) {}

  explicit AeadOrDaead(
      std::unique_ptr<DeterministicAead> deterministic_aead_primitive)
      : primitive_variant_(std::move(deterministic_aead_primitive)) {}

  // Encrypts 'plaintext' using the underlying aead or determnistic aead
  // primitive, and returns the resulting ciphertext.
  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext, absl::string_view associated_data) const;

  // Decrypts 'ciphertext' using the underlying aead or determnistic aead
  // primitive, and returns the resulting plaintext.
  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext, absl::string_view associated_data) const;

 private:
  absl::variant<std::unique_ptr<const Aead>,
                std::unique_ptr<const DeterministicAead>>
      primitive_variant_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_SUBTLE_AEAD_OR_DAEAD_H_
