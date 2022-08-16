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

#include "tink/experimental/pqcrypto/signature/subtle/falcon_sign.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/falcon-1024/api.h"
#include "third_party/pqclean/crypto_sign/falcon-512/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<PublicKeySign>> FalconSign::New(
    const FalconPrivateKeyPqclean& key) {
  auto status = internal::CheckFipsCompatibility<FalconSign>();
  if (!status.ok()) return status;

  return {absl::WrapUnique(new FalconSign(key))};
}

util::StatusOr<std::string> FalconSign::Sign(absl::string_view data) const {
  size_t sig_length;
  int32_t key_size = private_key_.GetKey().size();
  std::string signature;
  int result = 1;

  switch (key_size) {
    case kFalcon512PrivateKeySize: {
      signature.resize(PQCLEAN_FALCON512_CRYPTO_BYTES, '0');
      result = PQCLEAN_FALCON512_crypto_sign_signature(
          reinterpret_cast<uint8_t *>(signature.data()), &sig_length,
          reinterpret_cast<const uint8_t *>(data.data()), data.size(),
          reinterpret_cast<const uint8_t *>(private_key_.GetKey().data()));
      if (sig_length > PQCLEAN_FALCON512_CRYPTO_BYTES) {
        result = -1;
      }
      break;
    }
    case kFalcon1024PrivateKeySize: {
      signature.resize(PQCLEAN_FALCON1024_CRYPTO_BYTES, '0');
      result = PQCLEAN_FALCON1024_crypto_sign_signature(
          reinterpret_cast<uint8_t *>(signature.data()), &sig_length,
          reinterpret_cast<const uint8_t *>(data.data()), data.size(),
          reinterpret_cast<const uint8_t *>(private_key_.GetKey().data()));
      if (sig_length > PQCLEAN_FALCON1024_CRYPTO_BYTES) {
        result = -1;
      }
      break;
    }
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid keysize.");
  }

  if (result != 0) {
    return util::Status(absl::StatusCode::kInternal, "Signing failed.");
  }

  signature.resize(sig_length);
  return signature;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
