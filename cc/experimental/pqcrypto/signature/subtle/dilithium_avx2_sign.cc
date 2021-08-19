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

#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_sign.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/public_key_sign.h"
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
util::StatusOr<std::unique_ptr<PublicKeySign>> DilithiumAvx2Sign::New(
    DilithiumPrivateKeyPqclean private_key) {
  auto status = internal::CheckFipsCompatibility<DilithiumAvx2Sign>();
  if (!status.ok()) return status;

  uint32 key_size = private_key.GetKeyData().size();

  if (key_size != PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES &&
      key_size != PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES &&
      key_size != PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrFormat("Invalid private key size (%d). "
                        "The only valid sizes are %d, %d, %d.",
                        private_key.GetKeyData().size(),
                        PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES,
                        PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES,
                        PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES));
  }

  return {absl::WrapUnique(new DilithiumAvx2Sign(std::move(private_key)))};
}

util::StatusOr<std::string> DilithiumAvx2Sign::Sign(
    absl::string_view data) const {
  size_t sig_length;
  uint32 key_size = private_key_.GetKeyData().size();
  std::string signature;

  switch (key_size) {
    case PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES: {
      signature.resize(PQCLEAN_DILITHIUM2_AVX2_CRYPTO_BYTES, '0');
      if (PQCLEAN_DILITHIUM2_AVX2_crypto_sign_signature(
              reinterpret_cast<uint8_t *>(signature.data()), &sig_length,
              reinterpret_cast<const uint8_t *>(data.data()), data.size(),
              reinterpret_cast<const uint8_t *>(
                  private_key_.GetKeyData().data())) != 0) {
        return util::Status(util::error::INTERNAL, "Signing failed.");
      }
      break;
    }
    case PQCLEAN_DILITHIUM3_AVX2_CRYPTO_SECRETKEYBYTES: {
      signature.resize(PQCLEAN_DILITHIUM3_AVX2_CRYPTO_BYTES, '0');
      if (PQCLEAN_DILITHIUM3_AVX2_crypto_sign_signature(
              reinterpret_cast<uint8_t *>(signature.data()), &sig_length,
              reinterpret_cast<const uint8_t *>(data.data()), data.size(),
              reinterpret_cast<const uint8_t *>(
                  private_key_.GetKeyData().data())) != 0) {
        return util::Status(util::error::INTERNAL, "Signing failed.");
      }
      break;
    }
    case PQCLEAN_DILITHIUM5_AVX2_CRYPTO_SECRETKEYBYTES: {
      signature.resize(PQCLEAN_DILITHIUM5_AVX2_CRYPTO_BYTES, '0');
      if (PQCLEAN_DILITHIUM5_AVX2_crypto_sign_signature(
              reinterpret_cast<uint8_t *>(signature.data()), &sig_length,
              reinterpret_cast<const uint8_t *>(data.data()), data.size(),
              reinterpret_cast<const uint8_t *>(
                  private_key_.GetKeyData().data())) != 0) {
        return util::Status(util::error::INTERNAL, "Signing failed.");
      }
      break;
    }
    default:
      return util::Status(util::error::INTERNAL, "Invalid keysize.");
  }

  return signature;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
