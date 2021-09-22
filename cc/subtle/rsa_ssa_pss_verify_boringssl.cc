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

#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<RsaSsaPssVerifyBoringSsl>>
RsaSsaPssVerifyBoringSsl::New(
    const SubtleUtilBoringSSL::RsaPublicKey& pub_key,
    const SubtleUtilBoringSSL::RsaSsaPssParams& params) {
  auto status = internal::CheckFipsCompatibility<RsaSsaPssVerifyBoringSsl>();
  if (!status.ok()) return status;

  // Check hash.
  auto hash_status =
      SubtleUtilBoringSSL::ValidateSignatureHash(params.sig_hash);
  if (!hash_status.ok()) {
    return hash_status;
  }
  auto sig_hash_result = SubtleUtilBoringSSL::EvpHash(params.sig_hash);
  if (!sig_hash_result.ok()) return sig_hash_result.status();

  // TODO(quannguyen): check mgf1_hash function and salt length.
  auto mgf1_hash_result = SubtleUtilBoringSSL::EvpHash(params.mgf1_hash);
  if (!mgf1_hash_result.ok()) return mgf1_hash_result.status();

  // The RSA modulus and exponent are checked as part of the conversion to
  // bssl::UniquePtr<RSA>.
  auto rsa = SubtleUtilBoringSSL::BoringSslRsaFromRsaPublicKey(pub_key);
  if (!rsa.ok()) {
    return rsa.status();
  }

  std::unique_ptr<RsaSsaPssVerifyBoringSsl> verify(new RsaSsaPssVerifyBoringSsl(
      std::move(rsa).ValueOrDie(), sig_hash_result.ValueOrDie(),
      mgf1_hash_result.ValueOrDie(), params.salt_length));
  return std::move(verify);
}

util::Status RsaSsaPssVerifyBoringSsl::Verify(absl::string_view signature,
                                              absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = SubtleUtilBoringSSL::EnsureNonNull(data);

  auto digest_result = boringssl::ComputeHash(data, *sig_hash_);
  if (!digest_result.ok()) return digest_result.status();
  auto digest = std::move(digest_result.ValueOrDie());

  if (1 != RSA_verify_pss_mgf1(
               rsa_.get(), digest.data(), digest.size(), sig_hash_, mgf1_hash_,
               salt_length_, reinterpret_cast<const uint8_t*>(signature.data()),
               signature.length())) {
    // Signature is invalid.
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Signature is not valid.");
  }
  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
