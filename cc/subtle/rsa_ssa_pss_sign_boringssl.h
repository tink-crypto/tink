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

#ifndef TINK_SUBTLE_RSA_SSA_PSS_SIGN_BORINGSSL_H_
#define TINK_SUBTLE_RSA_SSA_PSS_SIGN_BORINGSSL_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "openssl/ec.h"
#include "openssl/rsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_sign.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// The RSA SSA (Signature Schemes with Appendix) using PSS (Probabilistic
// Signature Scheme) encoding is defined at
// https://tools.ietf.org/html/rfc8017#section-8.1). This implemention uses
// Boring SSL for the underlying cryptographic operations.
class RsaSsaPssSignBoringSsl : public PublicKeySign {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const internal::RsaPrivateKey& private_key,
      const internal::RsaSsaPssParams& params);

  // Computes the signature for 'data'.
  crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const override;

  ~RsaSsaPssSignBoringSsl() override = default;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  const internal::SslUniquePtr<RSA> private_key_;
  const EVP_MD* sig_hash_;   // Owned by BoringSSL.
  const EVP_MD* mgf1_hash_;  // Owned by BoringSSL.
  int32_t salt_length_;

  RsaSsaPssSignBoringSsl(internal::SslUniquePtr<RSA> private_key,
                         const EVP_MD* sig_hash, const EVP_MD* mgf1_hash,
                         int32_t salt_length);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_RSA_SSA_PSS_SIGN_BORINGSSL_H_
