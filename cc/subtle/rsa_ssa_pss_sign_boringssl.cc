// Copyright 2018 Google Inc.
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

#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"

#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/internal/err_util.h"
#include "tink/internal/md_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

util::StatusOr<std::unique_ptr<PublicKeySign>> RsaSsaPssSignBoringSsl::New(
    const internal::RsaPrivateKey& private_key,
    const internal::RsaSsaPssParams& params) {
  util::Status status =
      internal::CheckFipsCompatibility<RsaSsaPssSignBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  // Check if the hash type is safe to use.
  util::Status is_safe = internal::IsHashTypeSafeForSignature(params.sig_hash);
  if (!is_safe.ok()) {
    return is_safe;
  }

  util::StatusOr<const EVP_MD*> sig_hash =
      internal::EvpHashFromHashType(params.sig_hash);
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }

  util::StatusOr<const EVP_MD*> mgf1_hash =
      internal::EvpHashFromHashType(params.mgf1_hash);
  if (!mgf1_hash.ok()) {
    return mgf1_hash.status();
  }

  // The RSA modulus and exponent are checked as part of the conversion to
  // internal::SslUniquePtr<RSA>.
  util::StatusOr<internal::SslUniquePtr<RSA>> rsa =
      internal::RsaPrivateKeyToRsa(private_key);
  if (!rsa.ok()) {
    return rsa.status();
  }

  return {absl::WrapUnique(new RsaSsaPssSignBoringSsl(
      *std::move(rsa), *sig_hash, *mgf1_hash, params.salt_length))};
}

RsaSsaPssSignBoringSsl::RsaSsaPssSignBoringSsl(
    internal::SslUniquePtr<RSA> private_key, const EVP_MD* sig_hash,
    const EVP_MD* mgf1_hash, int32_t salt_length)
    : private_key_(std::move(private_key)),
      sig_hash_(sig_hash),
      mgf1_hash_(mgf1_hash),
      salt_length_(salt_length) {}

util::StatusOr<std::string> RsaSsaPssSignBoringSsl::Sign(
    absl::string_view data) const {
  data = internal::EnsureStringNonNull(data);
  util::StatusOr<std::string> digest = internal::ComputeHash(data, *sig_hash_);
  if (!digest.ok()) {
    return digest.status();
  }

  std::string signature;
  ResizeStringUninitialized(&signature, RSA_size(private_key_.get()));
  size_t signature_length;

  if (RSA_sign_pss_mgf1(
          private_key_.get(),
          /*out_len=*/&signature_length,
          /*out=*/reinterpret_cast<uint8_t*>(&signature[0]),
          /*max_out=*/signature.size(),
          /*digest=*/reinterpret_cast<const uint8_t*>(digest->data()),
          /*digest_len=*/digest->size(),
          /*md=*/sig_hash_,
          /*mgf1_md=*/mgf1_hash_, salt_length_) != 1) {
    // TODO(b/112581512): Decide if it's safe to propagate the BoringSSL error.
    // For now, just empty the error stack.
    internal::GetSslErrors();
    return util::Status(absl::StatusCode::kInternal, "Signing failed.");
  }
  signature.resize(signature_length);
  return signature;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
