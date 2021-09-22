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

#include "tink/experimental/pqcrypto/signature/subtle/sphincs_subtle_utils.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_helper_pqclean.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

crypto::tink::util::StatusOr<SphincsKeyPair> GenerateSphincsKeyPair(
    SphincsParamsPqclean params) {
  // Check if parameters are valid.
  util::Status valid_parameters = ValidateParams(params);
  if (!valid_parameters.ok()) {
    return valid_parameters;
  }

  util::StatusOr<int32> key_size_index =
      SphincsKeySizeToIndex(params.private_key_size);
  if (!key_size_index.ok()) {
    return key_size_index.status();
  }

  std::string public_key;
  std::string private_key;
  private_key.resize(params.private_key_size);

  const SphincsHelperPqclean &sphincs_helper_pqclean =
      GetSphincsHelperPqclean(params.hash_type, params.variant, *key_size_index,
                              params.sig_length_type);
  public_key.resize(sphincs_helper_pqclean.GetPublicKeySize());

  if (0 != sphincs_helper_pqclean.Keygen(
               reinterpret_cast<uint8_t *>(public_key.data()),
               reinterpret_cast<uint8_t *>(private_key.data()))) {
    return util::Status(util::error::INTERNAL, "Key generation failed.");
  }

  util::SecretData private_key_data =
      util::SecretDataFromStringView(private_key);

  SphincsKeyPair key_pair(SphincsPrivateKeyPqclean{private_key_data, params},
                          SphincsPublicKeyPqclean{public_key, params});

  return key_pair;
}

crypto::tink::util::Status ValidatePrivateKeySize(int32 key_size) {
  switch (key_size) {
    case kSphincsPrivateKeySize64:
    case kSphincsPrivateKeySize96:
    case kSphincsPrivateKeySize128:
      return util::OkStatus();
    default:
      return util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrFormat("Invalid private key size (%d). "
                          "The only valid sizes are %d, %d, %d.",
                          key_size, kSphincsPrivateKeySize64,
                          kSphincsPrivateKeySize96, kSphincsPrivateKeySize128));
  }
}

crypto::tink::util::Status ValidatePublicKeySize(int32 key_size) {
  switch (key_size) {
    case kSphincsPublicKeySize32:
    case kSphincsPublicKeySize48:
    case kSphincsPublicKeySize64:
      return util::OkStatus();
    default:
      return util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrFormat("Invalid private key size (%d). "
                          "The only valid sizes are %d, %d, %d.",
                          key_size, kSphincsPublicKeySize32,
                          kSphincsPublicKeySize48, kSphincsPublicKeySize64));
  }
}

crypto::tink::util::StatusOr<int32> SphincsKeySizeToIndex(int32 key_size) {
  switch (key_size) {
    case kSphincsPrivateKeySize64:
      return 0;
    case kSphincsPrivateKeySize96:
      return 1;
    case kSphincsPrivateKeySize128:
      return 2;
    default:
      return util::Status(util::error::INVALID_ARGUMENT, "Invalid key size");
  }
}

crypto::tink::util::Status ValidateParams(SphincsParamsPqclean params) {
  switch (params.hash_type) {
    case SphincsHashType::HARAKA:
    case SphincsHashType::SHA256:
    case SphincsHashType::SHAKE256: {
      break;
    }
    default: {
      return util::Status(util::error::INVALID_ARGUMENT, "Invalid hash type");
    }
  }

  switch (params.variant) {
    case SphincsVariant::ROBUST:
    case SphincsVariant::SIMPLE: {
      break;
    }
    default: {
      return util::Status(util::error::INVALID_ARGUMENT, "Invalid variant");
    }
  }

  switch (params.sig_length_type) {
    case SphincsSignatureType::FAST_SIGNING:
    case SphincsSignatureType::SMALL_SIGNATURE: {
      break;
    }
    default: {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "Invalid signature type");
    }
  }

  return ValidatePrivateKeySize(params.private_key_size);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
