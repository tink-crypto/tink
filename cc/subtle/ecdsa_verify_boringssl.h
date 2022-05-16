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

#ifndef TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_
#define TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_

#include <memory>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

// ECDSA verification using Boring SSL, accepting signatures in DER-encoding.
class EcdsaVerifyBoringSsl : public PublicKeyVerify {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>>
  New(const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
      EcdsaSignatureEncoding encoding);

  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>>
  New(internal::SslUniquePtr<EC_KEY> ec_key, HashType hash_type,
      EcdsaSignatureEncoding encoding);

  // Verifies that 'signature' is a digital signature for 'data'.
  crypto::tink::util::Status Verify(
      absl::string_view signature,
      absl::string_view data) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  EcdsaVerifyBoringSsl(internal::SslUniquePtr<EC_KEY> key, const EVP_MD* hash,
                       EcdsaSignatureEncoding encoding)
      : key_(std::move(key)), hash_(hash), encoding_(encoding) {}

  internal::SslUniquePtr<EC_KEY> key_;
  const EVP_MD* hash_;  // Owned by BoringSSL.
  EcdsaSignatureEncoding encoding_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_
