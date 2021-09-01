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

#include "tink/experimental/pqcrypto/signature/dilithium_verify_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_verify.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"
#include "tink/public_key_verify.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/avx2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/avx2/api.h"
}

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::DilithiumPublicKeyPqclean;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::DilithiumPublicKey;

StatusOr<std::unique_ptr<PublicKeyVerify>>
DilithiumVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const DilithiumPublicKey& public_key) const {
  util::StatusOr<DilithiumPublicKeyPqclean> dilithium_public_key =
      DilithiumPublicKeyPqclean::NewPublicKey(
          public_key.key_value(),
          subtle::DilithiumSeedExpansion::SHAKE_SEED_EXPANSION);

  if (!dilithium_public_key.ok()) return dilithium_public_key.status();

  return subtle::DilithiumAvx2Verify::New(*dilithium_public_key);
}

Status DilithiumVerifyKeyManager::ValidateKey(
    const DilithiumPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;

  if (key.key_value().length() !=
          PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES &&
      key.key_value().length() !=
          PQCLEAN_DILITHIUM3_AVX2_CRYPTO_PUBLICKEYBYTES &&
      key.key_value().length() !=
          PQCLEAN_DILITHIUM5_AVX2_CRYPTO_PUBLICKEYBYTES) {
    return Status(util::error::INVALID_ARGUMENT,
                  "Invalid dilithium public key size.");
  }
  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
