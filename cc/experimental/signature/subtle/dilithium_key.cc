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

#include "tink/experimental/signature/subtle/dilithium_key.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/sign.h"
}

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<DilithiumPrivateKey> DilithiumPrivateKey::NewPrivateKey(
    util::SecretData key_data) {
  return DilithiumPrivateKey(key_data);
}

// static
util::StatusOr<std::pair<DilithiumPrivateKey, DilithiumPublicKey>>
DilithiumPrivateKey::GenerateKeyPair() {
  std::string public_key;
  public_key.resize(PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES);

  std::string private_key;
  private_key.resize(PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES);

  PQCLEAN_DILITHIUM2_AVX2_crypto_sign_keypair(
      reinterpret_cast<uint8_t*>(public_key.data()),
      reinterpret_cast<uint8_t*>(private_key.data()));

  util::SecretData private_key_data =
      util::SecretDataFromStringView(private_key);

  util::StatusOr<DilithiumPrivateKey> dilithium_private_key =
      DilithiumPrivateKey::NewPrivateKey(std::move(private_key_data));
  util::StatusOr<DilithiumPublicKey> dilithium_public_key =
      DilithiumPublicKey::NewPublicKey(public_key);

  return std::make_pair(*dilithium_private_key, *dilithium_public_key);
}

const util::SecretData& DilithiumPrivateKey::GetKeyData() const {
  return key_data_;
}

// static
util::StatusOr<DilithiumPublicKey> DilithiumPublicKey::NewPublicKey(
    absl::string_view key_data) {
  return DilithiumPublicKey(key_data);
}

const std::string& DilithiumPublicKey::GetKeyData() const { return key_data_; }

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
