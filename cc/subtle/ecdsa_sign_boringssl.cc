// Copyright 2017 Google Inc.
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

#include "tink/subtle/ecdsa_sign_boringssl.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "openssl/evp.h"
#include "tink/internal/md_util.h"
#include "tink/internal/util.h"
#include "tink/signature/internal/ecdsa_raw_sign_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

util::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> EcdsaSignBoringSsl::New(
    const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding) {
  auto status = internal::CheckFipsCompatibility<EcdsaSignBoringSsl>();
  if (!status.ok()) return status;

  // Check if the hash type is safe to use.
  util::Status is_safe = internal::IsHashTypeSafeForSignature(hash_type);
  if (!is_safe.ok()) {
    return is_safe;
  }
  util::StatusOr<const EVP_MD*> hash = internal::EvpHashFromHashType(hash_type);
  if (!hash.ok()) {
    return hash.status();
  }

  util::StatusOr<std::unique_ptr<internal::EcdsaRawSignBoringSsl>> raw_sign =
      internal::EcdsaRawSignBoringSsl::New(ec_key, encoding);
  if (!raw_sign.ok()) return raw_sign.status();

  return {
      absl::WrapUnique(new EcdsaSignBoringSsl(*hash, std::move(*raw_sign)))};
}

util::StatusOr<std::string> EcdsaSignBoringSsl::Sign(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  // Compute the digest.
  unsigned int digest_size;
  uint8_t digest[EVP_MAX_MD_SIZE];
  if (1 != EVP_Digest(data.data(), data.size(), digest, &digest_size, hash_,
                      nullptr)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Could not compute digest.");
  }

  // Compute the signature.
  return raw_signer_->Sign(
      absl::string_view(reinterpret_cast<char*>(digest), digest_size));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
