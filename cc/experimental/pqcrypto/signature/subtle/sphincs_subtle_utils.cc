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
#include "tink/util/statusor.h"

// Definitions of the three possible sphincs key sizes.
#define SPHINCSKEYSIZE64 64
#define SPHINCSKEYSIZE96 96
#define SPHINCSKEYSIZE128 128

namespace crypto {
namespace tink {
namespace subtle {

crypto::tink::util::StatusOr<SphincsKeyPair> GenerateSphincsKeyPair(
    SphincsParams params) {
  util::Status key_size_status = ValidateKeySize(params.private_key_size);
  if (!key_size_status.ok()) {
    return key_size_status;
  }

  util::StatusOr<int32> key_size_index_or =
      SphincsKeySizeToIndex(params.private_key_size);
  if (!key_size_index_or.ok()) {
    return key_size_index_or.status();
  }

  std::string public_key;
  std::string private_key;
  private_key.resize(params.private_key_size);

  const SphincsHelperPqclean &sphincs_helper_pqclean =
      GetSphincsHelperPqclean(params.hash_type, params.variant,
                              *key_size_index_or, params.sig_length_type);
  public_key.resize(sphincs_helper_pqclean.GetPublicKeySize());

  if (0 != sphincs_helper_pqclean.Keygen(
               reinterpret_cast<uint8_t *>(public_key.data()),
               reinterpret_cast<uint8_t *>(private_key.data()))) {
    return util::Status(util::error::INTERNAL, "Key generation failed.");
  }

  util::SecretData private_key_data =
      util::SecretDataFromStringView(private_key);

  SphincsKeyPair key_pair(SphincsPrivateKeyPqclean{private_key_data},
                          SphincsPublicKeyPqclean{public_key});

  return key_pair;
}

crypto::tink::util::Status ValidateKeySize(int32 key_size) {
  switch (key_size) {
    case SPHINCSKEYSIZE64:
    case SPHINCSKEYSIZE96:
    case SPHINCSKEYSIZE128:
      return util::Status::OK;
    default:
      return util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrFormat("Invalid private key size (%d). "
                          "The only valid sizes are %d, %d, %d.",
                          key_size, SPHINCSKEYSIZE64, SPHINCSKEYSIZE96,
                          SPHINCSKEYSIZE128));
  }
}

crypto::tink::util::StatusOr<int32> SphincsKeySizeToIndex(int32 key_size) {
  switch (key_size) {
    case SPHINCSKEYSIZE64:
      return 0;
    case SPHINCSKEYSIZE96:
      return 1;
    case SPHINCSKEYSIZE128:
      return 2;
    default:
      return util::Status(util::error::INVALID_ARGUMENT, "Invalid key size");
  }
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
