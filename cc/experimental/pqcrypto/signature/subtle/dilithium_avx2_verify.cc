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

#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_verify.h"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"
#include "tink/public_key_verify.h"
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
util::StatusOr<std::unique_ptr<PublicKeyVerify>> DilithiumAvx2Verify::New(
    DilithiumPublicKeyPqclean public_key) {
  auto status = internal::CheckFipsCompatibility<DilithiumAvx2Verify>();
  if (!status.ok()) return status;

  int32_t key_size = public_key.GetKeyData().size();

  if (key_size != PQCLEAN_DILITHIUM2_CRYPTO_PUBLICKEYBYTES &&
      key_size != PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES &&
      key_size != PQCLEAN_DILITHIUM5_CRYPTO_PUBLICKEYBYTES) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid public key size (%d). "
                        "The only valid sizes are %d, %d, %d.",
                        key_size, PQCLEAN_DILITHIUM2_CRYPTO_PUBLICKEYBYTES,
                        PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES,
                        PQCLEAN_DILITHIUM5_CRYPTO_PUBLICKEYBYTES));
  }

  return {absl::WrapUnique(new DilithiumAvx2Verify(std::move(public_key)))};
}

util::Status DilithiumAvx2Verify::Verify(absl::string_view signature,
                                         absl::string_view data) const {
  int32_t key_size = public_key_.GetKeyData().size();
  int result = 1;

  switch (key_size) {
    case PQCLEAN_DILITHIUM2_CRYPTO_PUBLICKEYBYTES: {
      switch (public_key_.GetSeedExpansion()) {
        case DilithiumSeedExpansion::SEED_EXPANSION_AES: {
          result = PQCLEAN_DILITHIUM2AES_crypto_sign_verify(
              reinterpret_cast<const uint8_t *>(signature.data()),
              signature.size(), reinterpret_cast<const uint8_t *>(data.data()),
              data.size(),
              reinterpret_cast<const uint8_t *>(
                  public_key_.GetKeyData().data()));

          break;
        }
        case DilithiumSeedExpansion::SEED_EXPANSION_SHAKE: {
          result = PQCLEAN_DILITHIUM2_crypto_sign_verify(
              reinterpret_cast<const uint8_t *>(signature.data()),
              signature.size(), reinterpret_cast<const uint8_t *>(data.data()),
              data.size(),
              reinterpret_cast<const uint8_t *>(
                  public_key_.GetKeyData().data()));
          break;
        }
        default: {
          return util::Status(absl::StatusCode::kInternal,
                              "Invalid seed expansion.");
        }
      }
      break;
    }
    case PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES: {
      switch (public_key_.GetSeedExpansion()) {
        case DilithiumSeedExpansion::SEED_EXPANSION_AES: {
          result = PQCLEAN_DILITHIUM3AES_crypto_sign_verify(
              reinterpret_cast<const uint8_t *>(signature.data()),
              signature.size(), reinterpret_cast<const uint8_t *>(data.data()),
              data.size(),
              reinterpret_cast<const uint8_t *>(
                  public_key_.GetKeyData().data()));
          break;
        }
        case DilithiumSeedExpansion::SEED_EXPANSION_SHAKE: {
          result = PQCLEAN_DILITHIUM3_crypto_sign_verify(
              reinterpret_cast<const uint8_t *>(signature.data()),
              signature.size(), reinterpret_cast<const uint8_t *>(data.data()),
              data.size(),
              reinterpret_cast<const uint8_t *>(
                  public_key_.GetKeyData().data()));
          break;
        }
        default: {
          return util::Status(absl::StatusCode::kInternal,
                              "Invalid seed expansion.");
        }
      }
      break;
    }
    case PQCLEAN_DILITHIUM5_CRYPTO_PUBLICKEYBYTES: {
      switch (public_key_.GetSeedExpansion()) {
        case DilithiumSeedExpansion::SEED_EXPANSION_AES: {
          result = PQCLEAN_DILITHIUM5AES_crypto_sign_verify(
              reinterpret_cast<const uint8_t *>(signature.data()),
              signature.size(), reinterpret_cast<const uint8_t *>(data.data()),
              data.size(),
              reinterpret_cast<const uint8_t *>(
                  public_key_.GetKeyData().data()));
          break;
        }
        case DilithiumSeedExpansion::SEED_EXPANSION_SHAKE: {
          result = PQCLEAN_DILITHIUM5_crypto_sign_verify(
              reinterpret_cast<const uint8_t *>(signature.data()),
              signature.size(), reinterpret_cast<const uint8_t *>(data.data()),
              data.size(),
              reinterpret_cast<const uint8_t *>(
                  public_key_.GetKeyData().data()));
          break;
        }
        default: {
          return util::Status(absl::StatusCode::kInternal,
                              "Invalid seed expansion.");
        }
      }
      break;
    }
    default:
      return util::Status(absl::StatusCode::kInternal, "Invalid keysize.");
  }

  if (result != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Signature is not valid.");
  }

  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
