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
#include "absl/types/span.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/internal/err_util.h"
#include "tink/internal/md_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// Computes an RSA-SSA PSS signature using `rsa_private_key` over `digest`;
// `digest` is the digest of the message to sign computed with `sig_md`,
// `mgf1_md` is the hash function for generating the mask (if nullptr, `sig_md`
// is used), and `salt_length` the salt length in bytes.
//
// This function is equivalent to BoringSSL's `RSA_sign_pss_mgf1`[1], and
// differs from it only in that it uses `RSA_private_encrypt` instead of
// `RSA_sign_raw`, because the latter is not defined in OpenSSL. In BoringSSL
// `RSA_private_encrypt` is essentially an alias for `RSA_sign_raw` [2].
//
// OpenSSL uses the same sequence of API calls [3].
//
// [1]https://github.com/google/boringssl/blob/master/crypto/fipsmodule/rsa/rsa.c#L557
// [2]https://github.com/google/boringssl/blob/master/crypto/fipsmodule/rsa/rsa.c#L315
// [3]https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pmeth.c#L181
util::StatusOr<std::string> SslRsaSsaPssSign(RSA* rsa_private_key,
                                             absl::string_view digest,
                                             const EVP_MD* sig_md,
                                             const EVP_MD* mgf1_md,
                                             int32_t salt_length) {
  const int kHashSize = EVP_MD_size(sig_md);
  // Make sure the size of the digest is correct.
  if (digest.size() != kHashSize) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Size of the digest doesn't match the one "
                                     "of the hashing algorithm; expected ",
                                     kHashSize, " got ", digest.size()));
  }
  const int kModulusSize = RSA_size(rsa_private_key);
  std::vector<uint8_t> temporary_buffer(kModulusSize);
  // This will write exactly kModulusSize bytes to temporary_buffer.
  if (RSA_padding_add_PKCS1_PSS_mgf1(
          /*rsa=*/rsa_private_key, /*EM=*/temporary_buffer.data(),
          /*mHash=*/reinterpret_cast<const uint8_t*>(digest.data()),
          /*Hash=*/sig_md,
          /*mgf1Hash=*/mgf1_md,
          /*sLen=*/salt_length) != 1) {
    internal::GetSslErrors();
    return util::Status(absl::StatusCode::kInternal,
                        "RSA_padding_add_PKCS1_PSS_mgf1 failed.");
  }
  std::string signature;
  ResizeStringUninitialized(&signature, kModulusSize);
  int signature_length = RSA_private_encrypt(
      /*flen=*/kModulusSize, /*from=*/temporary_buffer.data(),
      /*to=*/reinterpret_cast<uint8_t*>(&signature[0]),
      /*rsa=*/rsa_private_key,
      /*padding=*/RSA_NO_PADDING);
  if (signature_length < 0) {
    internal::GetSslErrors();
    return util::Status(absl::StatusCode::kInternal,
                        "RSA_private_encrypt failed.");
  }
  signature.resize(signature_length);
  return signature;
}

}  // namespace

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

util::StatusOr<std::string> RsaSsaPssSignBoringSsl::Sign(
    absl::string_view data) const {
  data = internal::EnsureStringNonNull(data);
  util::StatusOr<std::string> digest = internal::ComputeHash(data, *sig_hash_);
  if (!digest.ok()) {
    return digest.status();
  }

  util::StatusOr<std::string> signature = SslRsaSsaPssSign(
      private_key_.get(), *digest, sig_hash_, mgf1_hash_, salt_length_);
  if (!signature.ok()) {
    return util::Status(absl::StatusCode::kInternal, "Signing failed.");
  }
  return signature;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
