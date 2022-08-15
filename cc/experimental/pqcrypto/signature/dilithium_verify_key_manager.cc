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

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_avx2_verify.h"
#include "tink/experimental/pqcrypto/signature/subtle/dilithium_key.h"
#include "tink/experimental/pqcrypto/signature/util/enums.h"
#include "tink/public_key_verify.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/dilithium2/api.h"
#include "third_party/pqclean/crypto_sign/dilithium3/api.h"
#include "third_party/pqclean/crypto_sign/dilithium5/api.h"
}

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::DilithiumPublicKeyPqclean;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::DilithiumParams;
using ::google::crypto::tink::DilithiumPublicKey;
using ::google::crypto::tink::DilithiumSeedExpansion;
using ::crypto::tink::util::EnumsPqcrypto;

StatusOr<std::unique_ptr<PublicKeyVerify>>
DilithiumVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const DilithiumPublicKey& public_key) const {
  util::StatusOr<DilithiumPublicKeyPqclean> dilithium_public_key =
      DilithiumPublicKeyPqclean::NewPublicKey(
          public_key.key_value(),
          EnumsPqcrypto::ProtoToSubtle(public_key.params().seed_expansion()));

  if (!dilithium_public_key.ok()) return dilithium_public_key.status();

  return subtle::DilithiumAvx2Verify::New(*dilithium_public_key);
}

Status DilithiumVerifyKeyManager::ValidateKey(
    const DilithiumPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;

  if (key.key_value().length() != PQCLEAN_DILITHIUM2_CRYPTO_PUBLICKEYBYTES &&
      key.key_value().length() != PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES &&
      key.key_value().length() != PQCLEAN_DILITHIUM5_CRYPTO_PUBLICKEYBYTES) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Invalid dilithium public key size.");
  }
  return util::OkStatus();
}

Status DilithiumVerifyKeyManager::ValidateParams(
    const DilithiumParams& params) const {
  switch (params.seed_expansion()) {
    case DilithiumSeedExpansion::SEED_EXPANSION_SHAKE:
    case DilithiumSeedExpansion::SEED_EXPANSION_AES: {
      break;
    }
    default: {
      return Status(absl::StatusCode::kInvalidArgument,
                    "Invalid seed expansion");
    }
  }

  switch (params.key_size()) {
    case PQCLEAN_DILITHIUM2_CRYPTO_SECRETKEYBYTES:
    case PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES:
    case PQCLEAN_DILITHIUM5_CRYPTO_SECRETKEYBYTES: {
      break;
    }
    default: {
      return Status(absl::StatusCode::kInvalidArgument, "Invalid key size.");
    }
  }

  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
