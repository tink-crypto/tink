// Copyright 2019 Google Inc.
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

#include "tink/subtle/ed25519_sign_boringssl.h"

#include <algorithm>
#include <iterator>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/public_key_sign.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

constexpr int kEd25519SignatureLenInBytes = 64;

// static
util::StatusOr<std::unique_ptr<PublicKeySign>> Ed25519SignBoringSsl::New(
    util::SecretData private_key) {
  auto status = internal::CheckFipsCompatibility<Ed25519SignBoringSsl>();
  if (!status.ok()) return status;

  // OpenSSL/BoringSSL consider the ED25519's private key to be: private_key ||
  // public_key.
  const int kSslPrivateKeySize =
      internal::Ed25519KeyPrivKeySize() + internal::Ed25519KeyPubKeySize();

  if (private_key.size() != kSslPrivateKeySize) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid ED25519 private key size (%d). "
                        "The only valid size is %d.",
                        private_key.size(), kSslPrivateKeySize));
  }

  internal::SslUniquePtr<EVP_PKEY> ssl_priv_key(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, /*unused=*/nullptr, private_key.data(),
      internal::Ed25519KeyPrivKeySize()));
  if (ssl_priv_key == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_new_raw_private_key failed");
  }

  return {absl::WrapUnique(new Ed25519SignBoringSsl(std::move(ssl_priv_key)))};
}

util::StatusOr<std::string> Ed25519SignBoringSsl::Sign(
    absl::string_view data) const {
  data = internal::EnsureStringNonNull(data);

  uint8_t out_sig[kEd25519SignatureLenInBytes];
  std::fill(std::begin(out_sig), std::end(out_sig), 0);

  internal::SslUniquePtr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_create());
  size_t sig_len = kEd25519SignatureLenInBytes;
  // type must be set to nullptr with Ed25519.
  // See https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestSignInit.html.
  if (EVP_DigestSignInit(md_ctx.get(), /*pctx=*/nullptr, /*type=*/nullptr,
                         /*e=*/nullptr, priv_key_.get()) != 1 ||
      EVP_DigestSign(md_ctx.get(), out_sig, &sig_len,
                     /*data=*/reinterpret_cast<const uint8_t *>(data.data()),
                     data.size()) != 1) {
    return util::Status(absl::StatusCode::kInternal, "Signing failed.");
  }

  return std::string(reinterpret_cast<char *>(out_sig),
                     kEd25519SignatureLenInBytes);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
