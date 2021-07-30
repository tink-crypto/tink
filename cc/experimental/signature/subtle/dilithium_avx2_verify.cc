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

#include "tink/experimental/signature/subtle/dilithium_avx2_verify.h"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/public_key_verify.h"
#include "tink/util/statusor.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/sign.h"
}

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<PublicKeyVerify>> DilithiumAvx2Verify::New(
    DilithiumPublicKey public_key) {
  auto status = internal::CheckFipsCompatibility<DilithiumAvx2Verify>();
  if (!status.ok()) return status;

  if (public_key.GetKeyData().length() !=
      PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrFormat("Invalid public key size (%d). "
                        "The only valid size is %d.",
                        public_key.GetKeyData().length(),
                        PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES));
  }

  return {absl::WrapUnique(new DilithiumAvx2Verify(std::move(public_key)))};
}

util::Status DilithiumAvx2Verify::Verify(absl::string_view signature,
                                         absl::string_view data) const {
  if (signature.size() != PQCLEAN_DILITHIUM2_AVX2_CRYPTO_BYTES) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        absl::StrFormat("Invalid signature size (%d). "
                                        "The signature must be %d bytes long.",
                                        signature.size(),
                                        PQCLEAN_DILITHIUM2_AVX2_CRYPTO_BYTES));
  }

  if (0 !=
      PQCLEAN_DILITHIUM2_AVX2_crypto_sign_verify(
          reinterpret_cast<const uint8_t *>(signature.data()), signature.size(),
          reinterpret_cast<const uint8_t *>(data.data()), data.size(),
          reinterpret_cast<const uint8_t *>(public_key_.GetKeyData().data()))) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Signature is not valid.");
  }

  return util::Status::OK;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
