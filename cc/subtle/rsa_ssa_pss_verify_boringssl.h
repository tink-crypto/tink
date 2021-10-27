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

#ifndef TINK_SUBTLE_RSA_SSA_PSS_VERIFY_BORINGSSL_H_
#define TINK_SUBTLE_RSA_SSA_PSS_VERIFY_BORINGSSL_H_

#include <memory>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

// RSA SSA (Signature Schemes with Appendix) using  PSS  (Probabilistic
// Signature Scheme) encoding is defined at
// https://tools.ietf.org/html/rfc8017#section-8.1). This implemention uses
// Boring SSL for the underlying cryptographic operations.
class RsaSsaPssVerifyBoringSsl : public PublicKeyVerify {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<RsaSsaPssVerifyBoringSsl>>
  New(const SubtleUtilBoringSSL::RsaPublicKey& pub_key,
      const SubtleUtilBoringSSL::RsaSsaPssParams& params);

  // Verifies that 'signature' is a digital signature for 'data'.
  crypto::tink::util::Status Verify(absl::string_view signature,
                                    absl::string_view data) const override;

  ~RsaSsaPssVerifyBoringSsl() override = default;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  RsaSsaPssVerifyBoringSsl(internal::SslUniquePtr<RSA> rsa,
                           const EVP_MD* sig_hash, const EVP_MD* mgf1_hash,
                           int salt_length)
      : rsa_(std::move(rsa)),
        sig_hash_(sig_hash),
        mgf1_hash_(mgf1_hash),
        salt_length_(salt_length) {}

  const internal::SslUniquePtr<RSA> rsa_;
  const EVP_MD* const sig_hash_;   // Owned by BoringSSL.
  const EVP_MD* const mgf1_hash_;  // Owned by BoringSSL.
  int salt_length_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_RSA_SSA_PSS_VERIFY_BORINGSSL_H_
