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

#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "openssl/base.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/subtle/subtle_util_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<PublicKeySign>> RsaSsaPssSignBoringSsl::New(
    const SubtleUtilBoringSSL::RsaPrivateKey& private_key,
    const SubtleUtilBoringSSL::RsaSsaPssParams& params) {
  auto status = internal::CheckFipsCompatibility<RsaSsaPssSignBoringSsl>();
  if (!status.ok()) return status;

  // Check hash.
  util::Status sig_hash_valid =
      SubtleUtilBoringSSL::ValidateSignatureHash(params.sig_hash);
  if (!sig_hash_valid.ok()) return sig_hash_valid;
  auto sig_hash = SubtleUtilBoringSSL::EvpHash(params.sig_hash);
  if (!sig_hash.ok()) return sig_hash.status();
  auto mgf1_hash = SubtleUtilBoringSSL::EvpHash(params.mgf1_hash);
  if (!mgf1_hash.ok()) return mgf1_hash.status();

  // The RSA modulus and exponent are checked as part of the conversion to
  // bssl::UniquePtr<RSA>.
  auto rsa = SubtleUtilBoringSSL::BoringSslRsaFromRsaPrivateKey(private_key);
  if (!rsa.ok()) {
    return rsa.status();
  }

  return {absl::WrapUnique(new RsaSsaPssSignBoringSsl(
      std::move(rsa).ValueOrDie(), sig_hash.ValueOrDie(),
      mgf1_hash.ValueOrDie(), params.salt_length))};
}

RsaSsaPssSignBoringSsl::RsaSsaPssSignBoringSsl(bssl::UniquePtr<RSA> private_key,
                                               const EVP_MD* sig_hash,
                                               const EVP_MD* mgf1_hash,
                                               int32_t salt_length)
    : private_key_(std::move(private_key)),
      sig_hash_(sig_hash),
      mgf1_hash_(mgf1_hash),
      salt_length_(salt_length) {}

util::StatusOr<std::string> RsaSsaPssSignBoringSsl::Sign(
    absl::string_view data) const {
  data = SubtleUtilBoringSSL::EnsureNonNull(data);
  auto digest_or = boringssl::ComputeHash(data, *sig_hash_);
  if (!digest_or.ok()) return digest_or.status();
  std::vector<uint8_t> digest = std::move(digest_or.ValueOrDie());

  std::vector<uint8_t> signature(RSA_size(private_key_.get()));
  size_t signature_length;

  if (RSA_sign_pss_mgf1(private_key_.get(),
                        /*out_len=*/&signature_length,
                        /*out=*/signature.data(), /*max_out=*/signature.size(),
                        /*in=*/digest.data(), /*in_len=*/digest.size(),
                        /*md=*/sig_hash_,
                        /*mgf1_md=*/mgf1_hash_, salt_length_) != 1) {
    // TODO(b/112581512): Decide if it's safe to propagate the BoringSSL error.
    // For now, just empty the error stack.
    SubtleUtilBoringSSL::GetErrors();
    return util::Status(util::error::INTERNAL, "Signing failed.");
  }
  return std::string(reinterpret_cast<const char*>(signature.data()),
                     signature_length);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
