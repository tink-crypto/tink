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

#include "tink/subtle/ecdsa_verify_boringssl.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "tink/internal/err_util.h"
#include "tink/internal/md_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"

namespace crypto {
namespace tink {
namespace subtle {

util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> EcdsaVerifyBoringSsl::New(
    const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding) {
  // Check curve.
  auto group_result(SubtleUtilBoringSSL::GetEcGroup(ec_key.curve));
  if (!group_result.ok()) return group_result.status();
  internal::SslUniquePtr<EC_GROUP> group(group_result.ValueOrDie());
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group.get());

  // Check key.
  auto ec_point_result =
      SubtleUtilBoringSSL::GetEcPoint(ec_key.curve, ec_key.pub_x, ec_key.pub_y);
  if (!ec_point_result.ok()) return ec_point_result.status();
  internal::SslUniquePtr<EC_POINT> pub_key(ec_point_result.ValueOrDie());
  if (!EC_KEY_set_public_key(key.get(), pub_key.get())) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
  }
  return New(std::move(key), hash_type, encoding);
}

util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> EcdsaVerifyBoringSsl::New(
    internal::SslUniquePtr<EC_KEY> ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding) {
  util::Status status =
      internal::CheckFipsCompatibility<EcdsaVerifyBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  // Check if the hash type is safe to use.
  util::Status is_safe = internal::IsHashTypeSafeForSignature(hash_type);
  if (!is_safe.ok()) {
    return is_safe;
  }
  util::StatusOr<const EVP_MD*> hash = internal::EvpHashFromHashType(hash_type);
  if (!hash.ok()) {
    return hash.status();
  }
  std::unique_ptr<EcdsaVerifyBoringSsl> verify(
      new EcdsaVerifyBoringSsl(std::move(ec_key), *hash, encoding));
  return std::move(verify);
}

util::Status EcdsaVerifyBoringSsl::Verify(absl::string_view signature,
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

  std::string derSig(signature);
  if (encoding_ == subtle::EcdsaSignatureEncoding::IEEE_P1363) {
    const EC_GROUP* group = EC_KEY_get0_group(key_.get());
    auto status_or_der =
        SubtleUtilBoringSSL::EcSignatureIeeeToDer(group, signature);

    if (!status_or_der.ok()) {
      return status_or_der.status();
    }
    derSig = status_or_der.ValueOrDie();
  }

  // Verify the signature.
  if (1 != ECDSA_verify(0 /* unused */, digest, digest_size,
                        reinterpret_cast<const uint8_t*>(derSig.data()),
                        derSig.size(), key_.get())) {
    // signature is invalid
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Signature is not valid.");
  }
  // signature is valid
  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
