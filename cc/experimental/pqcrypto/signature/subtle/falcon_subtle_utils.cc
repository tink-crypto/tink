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

#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_helper_pqclean.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/falcon-1024/avx2/api.h"
#include "third_party/pqclean/crypto_sign/falcon-512/avx2/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<FalconPrivateKeyPqclean> FalconPrivateKeyPqclean::NewPrivateKey(
    const util::SecretData& key_data) {
  util::Status status = ValidateFalconPrivateKeySize(key_data.size());
  if (!status.ok()) {
    return status;
  }

  return FalconPrivateKeyPqclean(key_data);
}

// static
util::StatusOr<FalconPublicKeyPqclean> FalconPublicKeyPqclean::NewPublicKey(
    absl::string_view key_data) {
  util::Status status = ValidateFalconPublicKeySize(key_data.size());
  if (!status.ok()) {
    return status;
  }

  return FalconPublicKeyPqclean(key_data);
}

crypto::tink::util::StatusOr<FalconKeyPair> GenerateFalconKeyPair(
    int32_t private_key_size) {
  std::string public_key;
  std::string private_key;

  switch (private_key_size) {
    // Falcon512.
    case kFalcon512PrivateKeySize: {
      private_key.resize(private_key_size);
      public_key.resize(kFalcon512PublicKeySize);
      PQCLEAN_FALCON512_AVX2_crypto_sign_keypair(
          reinterpret_cast<uint8_t*>(public_key.data()),
          reinterpret_cast<uint8_t*>(private_key.data()));
      break;
    }
    // Falcon1024.
    case kFalcon1024PrivateKeySize: {
      private_key.resize(private_key_size);
      public_key.resize(kFalcon1024PublicKeySize);
      PQCLEAN_FALCON1024_AVX2_crypto_sign_keypair(
          reinterpret_cast<uint8_t*>(public_key.data()),
          reinterpret_cast<uint8_t*>(private_key.data()));
      break;
    }
    // Invalid key size.
    default: {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrFormat("Invalid private key size (%d). "
                          "The only valid sizes are %d, %d",
                          private_key_size, kFalcon512PrivateKeySize,
                          kFalcon1024PrivateKeySize));
    }
  }

  util::SecretData private_key_data =
      util::SecretDataFromStringView(private_key);

  util::StatusOr<FalconPrivateKeyPqclean> falcon_private_key =
      FalconPrivateKeyPqclean::NewPrivateKey(private_key_data);
  util::StatusOr<FalconPublicKeyPqclean> falcon_public_key =
      FalconPublicKeyPqclean::NewPublicKey(public_key);

  if (!falcon_private_key.ok() || !falcon_public_key.ok()) {
    return util::Status(absl::StatusCode::kInternal, "Key generation failed.");
  }

  FalconKeyPair key_pair(*falcon_private_key, *falcon_public_key);

  return key_pair;
}

crypto::tink::util::Status ValidateFalconPrivateKeySize(int32_t key_size) {
  switch (key_size) {
    case kFalcon512PrivateKeySize:
    case kFalcon1024PrivateKeySize:
      return util::Status::OK;
    default:
      return util::Status(util::error::INVALID_ARGUMENT,
                          absl::StrFormat("Invalid private key size (%d). "
                                          "The only valid sizes are %d, %d",
                                          key_size, kFalcon512PrivateKeySize,
                                          kFalcon1024PrivateKeySize));
  }
}

crypto::tink::util::Status ValidateFalconPublicKeySize(int32_t key_size) {
  switch (key_size) {
    case kFalcon512PublicKeySize:
    case kFalcon1024PublicKeySize:
      return util::Status::OK;
    default:
      return util::Status(util::error::INVALID_ARGUMENT,
                          absl::StrFormat("Invalid public key size (%d). "
                                          "The only valid sizes are %d, %d",
                                          key_size, kFalcon512PublicKeySize,
                                          kFalcon1024PublicKeySize));
  }
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
