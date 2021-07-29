// Copyright 2021 Google LLC
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

#ifndef TINK_EXPERIMENTAL_SIGNATURE_SUBTLE_DILITHIUM_KEY_H_
#define TINK_EXPERIMENTAL_SIGNATURE_SUBTLE_DILITHIUM_KEY_H_

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// Dilithium public key representation.
class DilithiumPublicKey {
 public:
  // Creates a new DilithiumPublicKey from key_data. Should only be called with
  // the result of a previous call to GetKeyData().
  static util::StatusOr<DilithiumPublicKey> NewPublicKey(
      std::string_view key_data);

  DilithiumPublicKey(const DilithiumPublicKey& other) = default;
  DilithiumPublicKey& operator=(const DilithiumPublicKey& other) = default;

  const std::string& GetKeyData() const;

 private:
  explicit DilithiumPublicKey(absl::string_view key_data)
      : key_data_(std::move(key_data)) {}

  const std::string key_data_;
};

// Dilithium private key representation.
class DilithiumPrivateKey {
 public:
  // Creates a new DilithiumPrivateKey from key_data. Should only be called with
  // the result of a previous call to GetKeyData().
  static util::StatusOr<DilithiumPrivateKey> NewPrivateKey(
      util::SecretData key_data);

  // Generates a new dilithium key pair.
  static util::StatusOr<std::pair<DilithiumPrivateKey, DilithiumPublicKey>>
  GenerateKeyPair();

  DilithiumPrivateKey(const DilithiumPrivateKey& other) = default;
  DilithiumPrivateKey& operator=(const DilithiumPrivateKey& other) = default;

  const util::SecretData& GetKeyData() const;

 private:
  explicit DilithiumPrivateKey(util::SecretData key_data)
      : key_data_(std::move(key_data)) {}

  const util::SecretData key_data_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_SIGNATURE_SUBTLE_DILITHIUM_KEY_H_
