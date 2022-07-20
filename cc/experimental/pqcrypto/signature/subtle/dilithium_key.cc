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
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium2aes/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3aes/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5aes/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<DilithiumPrivateKeyPqclean>
DilithiumPrivateKeyPqclean::NewPrivateKey(
    util::SecretData key_data, DilithiumSeedExpansion seed_expansion) {
  return DilithiumPrivateKeyPqclean(key_data, seed_expansion);
}

// static
util::StatusOr<std::pair<DilithiumPrivateKeyPqclean, DilithiumPublicKeyPqclean>>
DilithiumPrivateKeyPqclean::GenerateKeyPair(
    int32_t private_key_size, DilithiumSeedExpansion seed_expansion) {
  std::string public_key;
  std::string private_key;
  private_key.resize(private_key_size);

  // Check if the key_size parameter is correct.
  switch (private_key_size) {
    // Dilithium2.
    case PQCLEAN_DILITHIUM2_CRYPTO_SECRETKEYBYTES: {
      switch (seed_expansion) {
        case DilithiumSeedExpansion::SEED_EXPANSION_AES: {
          public_key.resize(PQCLEAN_DILITHIUM2AES_CRYPTO_PUBLICKEYBYTES);
          PQCLEAN_DILITHIUM2AES_crypto_sign_keypair(
              reinterpret_cast<uint8_t*>(public_key.data()),
              reinterpret_cast<uint8_t*>(private_key.data()));
          break;
        }
        case DilithiumSeedExpansion::SEED_EXPANSION_SHAKE: {
          public_key.resize(PQCLEAN_DILITHIUM2_CRYPTO_PUBLICKEYBYTES);
          PQCLEAN_DILITHIUM2_crypto_sign_keypair(
              reinterpret_cast<uint8_t*>(public_key.data()),
              reinterpret_cast<uint8_t*>(private_key.data()));
          break;
        }
        default: {
          return util::Status(absl::StatusCode::kInvalidArgument,
                              "Invalid seed expansion");
        }
      }
      break;
    }
    // Dilithium3.
    case PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES: {
      switch (seed_expansion) {
        case DilithiumSeedExpansion::SEED_EXPANSION_AES: {
          public_key.resize(PQCLEAN_DILITHIUM3AES_CRYPTO_PUBLICKEYBYTES);
          PQCLEAN_DILITHIUM3AES_crypto_sign_keypair(
              reinterpret_cast<uint8_t*>(public_key.data()),
              reinterpret_cast<uint8_t*>(private_key.data()));
          break;
        }
        case DilithiumSeedExpansion::SEED_EXPANSION_SHAKE: {
          public_key.resize(PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES);
          PQCLEAN_DILITHIUM3_crypto_sign_keypair(
              reinterpret_cast<uint8_t*>(public_key.data()),
              reinterpret_cast<uint8_t*>(private_key.data()));
          break;
        }
        default: {
          return util::Status(absl::StatusCode::kInvalidArgument,
                              "Invalid seed expansion");
        }
      }
      break;
    }
    // Dilithium5.
    case PQCLEAN_DILITHIUM5_CRYPTO_SECRETKEYBYTES: {
      switch (seed_expansion) {
        case DilithiumSeedExpansion::SEED_EXPANSION_AES: {
          public_key.resize(PQCLEAN_DILITHIUM5AES_CRYPTO_PUBLICKEYBYTES);
          PQCLEAN_DILITHIUM5AES_crypto_sign_keypair(
              reinterpret_cast<uint8_t*>(public_key.data()),
              reinterpret_cast<uint8_t*>(private_key.data()));
          break;
        }
        case DilithiumSeedExpansion::SEED_EXPANSION_SHAKE: {
          public_key.resize(PQCLEAN_DILITHIUM5_CRYPTO_PUBLICKEYBYTES);
          PQCLEAN_DILITHIUM5_crypto_sign_keypair(
              reinterpret_cast<uint8_t*>(public_key.data()),
              reinterpret_cast<uint8_t*>(private_key.data()));
          break;
        }
        default: {
          return util::Status(absl::StatusCode::kInvalidArgument,
                              "Invalid seed expansion");
        }
      }
      break;
    }
    // Invalid key size.
    default: {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrFormat("Invalid private key size (%d). "
                          "The only valid sizes are %d, %d, %d.",
                          private_key_size,
                          PQCLEAN_DILITHIUM2_CRYPTO_SECRETKEYBYTES,
                          PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES,
                          PQCLEAN_DILITHIUM5_CRYPTO_SECRETKEYBYTES));
    }
  }

  util::SecretData private_key_data =
      util::SecretDataFromStringView(private_key);

  util::StatusOr<DilithiumPrivateKeyPqclean> dilithium_private_key =
      DilithiumPrivateKeyPqclean::NewPrivateKey(std::move(private_key_data),
                                                seed_expansion);
  util::StatusOr<DilithiumPublicKeyPqclean> dilithium_public_key =
      DilithiumPublicKeyPqclean::NewPublicKey(public_key, seed_expansion);

  return std::make_pair(*dilithium_private_key, *dilithium_public_key);
}

const util::SecretData& DilithiumPrivateKeyPqclean::GetKeyData() const {
  return key_data_;
}

const DilithiumSeedExpansion& DilithiumPrivateKeyPqclean::GetSeedExpansion()
    const {
  return seed_expansion_;
}

// static
util::StatusOr<DilithiumPublicKeyPqclean>
DilithiumPublicKeyPqclean::NewPublicKey(absl::string_view key_data,
                                        DilithiumSeedExpansion seed_expansion) {
  return DilithiumPublicKeyPqclean(key_data, seed_expansion);
}

const std::string& DilithiumPublicKeyPqclean::GetKeyData() const {
  return key_data_;
}

const DilithiumSeedExpansion& DilithiumPublicKeyPqclean::GetSeedExpansion()
    const {
  return seed_expansion_;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
