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
#include "tink/internal/md_util.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/internal/err_util.h"
#include "tink/internal/util.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<const EVP_MD *> EvpHashFromHashType(subtle::HashType hash_type) {
  switch (hash_type) {
    case subtle::HashType::SHA1:
      return EVP_sha1();
    case subtle::HashType::SHA224:
      return EVP_sha224();
    case subtle::HashType::SHA256:
      return EVP_sha256();
    case subtle::HashType::SHA384:
      return EVP_sha384();
    case subtle::HashType::SHA512:
      return EVP_sha512();
    default:
      return util::Status(
          absl::StatusCode::kUnimplemented,
          absl::StrCat("Unsupported hash ", subtle::EnumToString(hash_type)));
  }
}

util::Status IsHashTypeSafeForSignature(subtle::HashType sig_hash) {
  switch (sig_hash) {
    case subtle::HashType::SHA256:
    case subtle::HashType::SHA384:
    case subtle::HashType::SHA512:
      return util::OkStatus();
    case subtle::HashType::SHA1:
    case subtle::HashType::SHA224:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Hash function ", subtle::EnumToString(sig_hash),
                       " is not safe for digital signature"));
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported hash function");
  }
}

util::StatusOr<std::string> ComputeHash(absl::string_view input,
                                        const EVP_MD &hasher) {
  input = EnsureStringNonNull(input);
  std::string digest;
  subtle::ResizeStringUninitialized(&digest, EVP_MAX_MD_SIZE);
  uint32_t digest_length = 0;
  if (EVP_Digest(input.data(), input.length(),
                 reinterpret_cast<uint8_t *>(&digest[0]), &digest_length,
                 &hasher, /*impl=*/nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Openssl internal error computing hash: ",
                                     internal::GetSslErrors()));
  }
  digest.resize(digest_length);
  return digest;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
