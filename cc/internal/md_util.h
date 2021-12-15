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
#ifndef TINK_INTERNAL_MD_UTIL_H_
#define TINK_INTERNAL_MD_UTIL_H_

#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns an EVP structure for a hash function type `hash_type`.
// Note: EVP_MD instances are sigletons owned by BoringSSL/OpenSSL.
util::StatusOr<const EVP_MD *> EvpHashFromHashType(
    crypto::tink::subtle::HashType hash_type);

// Validates whether `sig_hash` is safe to use for digital signature.
crypto::tink::util::Status IsHashTypeSafeForSignature(
    crypto::tink::subtle::HashType sig_hash);

// Returns the hash of `input` using the hash function `hasher`.
crypto::tink::util::StatusOr<std::string> ComputeHash(absl::string_view input,
                                                      const EVP_MD &hasher);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_MD_UTIL_H_
