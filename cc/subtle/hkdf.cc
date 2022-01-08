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

#include "tink/subtle/hkdf.h"

#include <string>

#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/evp.h"
// BoringSSL and OpenSSL have incompatible ways to compute HDKF: BoringSSL
// provides a one-shot API HKDF, while OpenSSL doesn't make that API public, but
// instead provides this functionality over the EVP interface, which in turn
// doesn't provide means to compute HKDF in BoringSSL. As a consequence, we need
// to selectively include the correct header and use different implementations.
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/hkdf.h"
#else
#include "openssl/kdf.h"
#endif
#include "tink/internal/md_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// Compute HKDF using `evp_md` hashing, key `ikm`, salt `salt` and info `info`.
// The result is written to `key`.
util::Status SslHkdf(const EVP_MD *evp_md, absl::string_view ikm,
                     absl::string_view salt, absl::string_view info,
                     absl::Span<uint8_t> out_key) {
#ifdef OPENSSL_IS_BORINGSSL
  if (HKDF(out_key.data(), out_key.size(), evp_md,
           reinterpret_cast<const uint8_t *>(ikm.data()), ikm.size(),
           reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
           reinterpret_cast<const uint8_t *>(info.data()), info.size()) != 1) {
    return util::Status(absl::StatusCode::kInternal, "HKDF failed");
  }
  return util::OkStatus();
#else
  internal::SslUniquePtr<EVP_PKEY_CTX> pctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, /*e=*/nullptr));
  if (pctx == nullptr || EVP_PKEY_derive_init(pctx.get()) <= 0 ||
      EVP_PKEY_CTX_set_hkdf_md(pctx.get(), evp_md) <= 0 ||
      EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(), salt.size()) <= 0 ||
      EVP_PKEY_CTX_set1_hkdf_key(pctx.get(),
                                 reinterpret_cast<const uint8_t *>(ikm.data()),
                                 ikm.size()) <= 0 ||
      EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info.data(), info.size()) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_CTX setup failed");
  }
  size_t output_length = out_key.size();
  if (EVP_PKEY_derive(pctx.get(), out_key.data(), &output_length) <= 0) {
    return util::Status(absl::StatusCode::kInternal, "HKDF failed");
  }
  return util::OkStatus();
#endif
}

}  // namespace

util::StatusOr<util::SecretData> Hkdf::ComputeHkdf(HashType hash,
                                                   const util::SecretData &ikm,
                                                   absl::string_view salt,
                                                   absl::string_view info,
                                                   size_t out_len) {
  util::StatusOr<const EVP_MD *> evp_md = internal::EvpHashFromHashType(hash);
  if (!evp_md.ok()) {
    return evp_md.status();
  }

  util::SecretData out_key(out_len);
  util::Status result =
      SslHkdf(*evp_md, util::SecretDataAsStringView(ikm), salt, info,
              absl::MakeSpan(out_key.data(), out_key.size()));
  if (!result.ok()) {
    return result;
  }
  return out_key;
}

util::StatusOr<std::string> Hkdf::ComputeHkdf(HashType hash,
                                              absl::string_view ikm,
                                              absl::string_view salt,
                                              absl::string_view info,
                                              size_t out_len) {
  util::StatusOr<const EVP_MD *> evp_md = internal::EvpHashFromHashType(hash);
  if (!evp_md.ok()) {
    return evp_md.status();
  }
  std::string out_key;
  ResizeStringUninitialized(&out_key, out_len);
  util::Status result = SslHkdf(
      *evp_md, ikm, salt, info,
      absl::MakeSpan(reinterpret_cast<uint8_t *>(&out_key[0]), out_key.size()));
  if (!result.ok()) {
    return result;
  }
  return out_key;
}

util::StatusOr<util::SecretData> Hkdf::ComputeEciesHkdfSymmetricKey(
    HashType hash, absl::string_view kem_bytes,
    const util::SecretData &shared_secret, absl::string_view salt,
    absl::string_view info, size_t out_len) {
  util::SecretData ikm(kem_bytes.size() + shared_secret.size());
  absl::c_copy(kem_bytes, ikm.begin());
  absl::c_copy(shared_secret, ikm.begin() + kem_bytes.size());
  return Hkdf::ComputeHkdf(hash, ikm, salt, info, out_len);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
