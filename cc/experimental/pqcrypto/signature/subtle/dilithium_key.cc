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

#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/avx2/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<DilithiumPrivateKeyPqclean>
DilithiumPrivateKeyPqclean::NewPrivateKey(util::SecretData key_data) {
  return DilithiumPrivateKeyPqclean(key_data);
}

// static
util::StatusOr<std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
DilithiumPrivateKeyPqclean::GenerateKeyPair(uint32 private_key_size) {
  std::string public_key;
  std::string private_key;
  private_key.resize(private_key_size);

  // Check if the key_size parameter is correct.
  switch (private_key_size) {
    // Dilithium2.
    case PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES: {
      public_key.resize(PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES);
      PQCLEAN_DILITHIUM2_AVX2_crypto_sign_keypair(
          reinterpret_cast<uint8_t*>(public_key.data()),
          reinterpret_cast<uint8_t*>(private_key.data()));
      break;
    }
    // Dilithium3.
    case PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES: {
      public_key.resize(PQCLEAN_DILITHIUM3_AVX2_CRYPTO_PUBLICKEYBYTES);
      PQCLEAN_DILITHIUM3_AVX2_crypto_sign_keypair(
          reinterpret_cast<uint8_t*>(public_key.data()),
          reinterpret_cast<uint8_t*>(private_key.data()));
      break;
    }
    // Dilithium5.
    case PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES: {
      public_key.resize(PQCLEAN_DILITHIUM5_AVX2_CRYPTO_PUBLICKEYBYTES);
      PQCLEAN_DILITHIUM5_AVX2_crypto_sign_keypair(
          reinterpret_cast<uint8_t*>(public_key.data()),
          reinterpret_cast<uint8_t*>(private_key.data()));
      break;
    }
    // Invalid key size.
    default: {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrFormat("Invalid private key size (%d). "
                          "The only valid sizes are %d, %d, %d.",
                          private_key_size,
                          PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES,
                          PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES,
                          PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES));
    }
  }

  util::SecretData private_key_data =
      util::SecretDataFromStringView(private_key);

  util::StatusOr<DilithiumPrivateKeyPqclean> dilithium_private_key =
      DilithiumPrivateKeyPqclean::NewPrivateKey(std::move(private_key_data));
  util::StatusOr<DilithiumPublicKeyPqclean> dilithium_public_key =
      DilithiumPublicKeyPqclean::NewPublicKey(public_key);

  return std::make_pair(*dilithium_private_key, *dilithium_public_key);
}

const util::SecretData& DilithiumPrivateKeyPqclean::GetKeyData() const {
  return key_data_;
}

// static
util::StatusOr<DilithiumPublicKeyPqclean>
DilithiumPublicKeyPqclean::NewPublicKey(absl::string_view key_data) {
  return DilithiumPublicKeyPqclean(key_data);
}

const std::string& DilithiumPublicKeyPqclean::GetKeyData() const {
  return key_data_;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
