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

#include "absl/strings/str_cat.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/mem.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

// Transforms ECDSA IEEE_P1363 signature encoding to DER encoding.
//
// The IEEE_P1363 signature's format is r || s, where r and s are zero-padded
// and have the same size in bytes as the order of the curve. For example, for
// NIST P-256 curve, r and s are zero-padded to 32 bytes.
//
// The DER signature is encoded using ASN.1
// (https://tools.ietf.org/html/rfc5480#appendix-A): ECDSA-Sig-Value :: =
// SEQUENCE { r INTEGER, s INTEGER }. In particular, the encoding is: 0x30 ||
// totalLength || 0x02 || r's length || r || 0x02 || s's length || s.
crypto::tink::util::StatusOr<std::string> IeeeToDer(absl::string_view ieee,
                                               const EC_KEY* key) {
  size_t field_size_in_bytes =
      (EC_GROUP_get_degree(EC_KEY_get0_group(key)) + 7) / 8;
  if (ieee.size() != field_size_in_bytes * 2) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Signature is not valid.");
  }
  bssl::UniquePtr<ECDSA_SIG> ecdsa(ECDSA_SIG_new());
  auto status_or_r =
      SubtleUtilBoringSSL::str2bn(ieee.substr(0, ieee.size() / 2));
  if (!status_or_r.ok()) {
    return status_or_r.status();
  }
  auto status_or_s = SubtleUtilBoringSSL::str2bn(
      ieee.substr(ieee.size() / 2, ieee.size() / 2));
  if (!status_or_s.ok()) {
    return status_or_s.status();
  }
  if (1 != ECDSA_SIG_set0(ecdsa.get(), status_or_r.ValueOrDie().get(),
                          status_or_s.ValueOrDie().get())) {
    return util::Status(util::error::INTERNAL, "ECDSA_SIG_set0 error.");
  }
  // ECDSA_SIG_set0 takes ownership of s and r's pointers.
  status_or_r.ValueOrDie().release();
  status_or_s.ValueOrDie().release();
  uint8_t* der = nullptr;
  bssl::UniquePtr<uint8_t> unique(der);
  size_t der_len;
  if (!ECDSA_SIG_to_bytes(&der, &der_len, ecdsa.get())) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ECDSA_SIG_to_bytes error");
  }
  return std::string(reinterpret_cast<char*>(der), der_len);
}
}  // namespace

// static
util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> EcdsaVerifyBoringSsl::New(
    const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding) {
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
  return New(std::move(key), hash_type, encoding);
}

// static
util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> EcdsaVerifyBoringSsl::New(
    bssl::UniquePtr<EC_KEY> ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding) {
  // Check hash.
  auto hash_status = SubtleUtilBoringSSL::ValidateSignatureHash(hash_type);
  if (!hash_status.ok()) {
    return hash_status;
  }
  auto hash_result = SubtleUtilBoringSSL::EvpHash(hash_type);
  if (!hash_result.ok()) return hash_result.status();
  const EVP_MD* hash = hash_result.ValueOrDie();
  std::unique_ptr<EcdsaVerifyBoringSsl> verify(
      new EcdsaVerifyBoringSsl(ec_key.release(), hash, encoding));
  return std::move(verify);
}

EcdsaVerifyBoringSsl::EcdsaVerifyBoringSsl(EC_KEY* key, const EVP_MD* hash,
                                           EcdsaSignatureEncoding encoding)
    : key_(key), hash_(hash), encoding_(encoding) {}

util::Status EcdsaVerifyBoringSsl::Verify(
    absl::string_view signature,
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = SubtleUtilBoringSSL::EnsureNonNull(data);

  // Compute the digest.
  unsigned int digest_size;
  uint8_t digest[EVP_MAX_MD_SIZE];
  if (1 != EVP_Digest(data.data(), data.size(), digest, &digest_size, hash_,
                  nullptr)) {
    return util::Status(util::error::INTERNAL, "Could not compute digest.");
  }

  std::string derSig(signature);
  if (encoding_ == subtle::EcdsaSignatureEncoding::IEEE_P1363) {
    auto status_or_der = IeeeToDer(signature, key_.get());
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
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Signature is not valid.");
  }
  // signature is valid
  return util::Status::OK;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
