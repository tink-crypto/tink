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

#include "cc/subtle/ecdsa_verify_boringssl.h"

#include "absl/strings/str_cat.h"
#include "cc/subtle/common_enums.h"
#include "cc/subtle/subtle_util_boringssl.h"
#include "cc/util/errors.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>>
EcdsaVerifyBoringSsl::New(const SubtleUtilBoringSSL::EcKey& ec_key,
                        HashType hash_type) {
  // Check hash.
  auto hash_result = SubtleUtilBoringSSL::EvpHash(hash_type);
  if (!hash_result.ok()) return hash_result.status();
  const EVP_MD* hash = hash_result.ValueOrDie();

  // Check curve.
  auto group_result(SubtleUtilBoringSSL::GetEcGroup(ec_key.curve));
  if (!group_result.ok()) return group_result.status();
  bssl::UniquePtr<EC_GROUP> group(group_result.ValueOrDie());
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group.get());

  // Check key.
  auto ec_point_result =
      SubtleUtilBoringSSL::GetEcPoint(ec_key.curve, ec_key.pub_x, ec_key.pub_y);
  if (!ec_point_result.ok()) return ec_point_result.status();
  bssl::UniquePtr<EC_POINT> pub_key(ec_point_result.ValueOrDie());
  if (!EC_KEY_set_public_key(key.get(), pub_key.get())) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        absl::StrCat("Invalid public key: ",
                                     SubtleUtilBoringSSL::GetErrors()));
  }
  std::unique_ptr<EcdsaVerifyBoringSsl> verify(
      new EcdsaVerifyBoringSsl(key.release(), hash));
  return std::move(verify);
}

EcdsaVerifyBoringSsl::EcdsaVerifyBoringSsl(EC_KEY* key, const EVP_MD* hash)
    : key_(key), hash_(hash) {}

util::Status EcdsaVerifyBoringSsl::Verify(
    absl::string_view signature,
    absl::string_view data) const {

  // Compute the digest.
  unsigned int digest_size;
  uint8_t digest[EVP_MAX_MD_SIZE];
  bssl::UniquePtr<EVP_MD_CTX> mdctx(EVP_MD_CTX_create());
  if (!EVP_DigestInit_ex(mdctx.get(), hash_, nullptr)) {
    return util::Status(util::error::INTERNAL, "Could not compute digest.");
  }
  if (!EVP_DigestUpdate(mdctx.get(), data.data(), data.size())) {
    return util::Status(util::error::INTERNAL, "Could not compute digest.");
  }
  if (!EVP_DigestFinal_ex(mdctx.get(), digest, &digest_size)) {
    return util::Status(util::error::INTERNAL, "Could not compute digest.");
  }

  // Verify the signature.
  const uint8_t* ptr = reinterpret_cast<const uint8_t*>(signature.data());
  bssl::UniquePtr<ECDSA_SIG> sig(
      d2i_ECDSA_SIG(nullptr, &ptr, signature.length()));
  int status = ECDSA_do_verify(digest, digest_size, sig.get(), key_.get());
  if (status == 1) {
    // signature is valid
    return util::Status::OK;
  } else if (status == 0) {
    // signature is invalid
    return util::Status(util::error::UNKNOWN,
                        "Signature is not valid.");
  } else {
    // an error occurred during the verification
    return util::Status(util::error::INTERNAL,
                        "An error occured during verification.");
  }
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
