// Copyright 2023 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/rsa_ssa_pkcs1_parameters.h"

#include <set>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#else
#include "openssl/bn.h"
#endif
#include "tink/big_integer.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

constexpr int kF4 = 65537;

}  // namespace

RsaSsaPkcs1Parameters::Builder&
RsaSsaPkcs1Parameters::Builder::SetModulusSizeInBits(int modulus_size_in_bits) {
  modulus_size_in_bits_ = modulus_size_in_bits;
  return *this;
}

RsaSsaPkcs1Parameters::Builder&
RsaSsaPkcs1Parameters::Builder::SetPublicExponent(
    const BigInteger& public_exponent) {
  public_exponent_ = public_exponent;
  return *this;
}

RsaSsaPkcs1Parameters::Builder& RsaSsaPkcs1Parameters::Builder::SetHashType(
    HashType hash_type) {
  hash_type_ = hash_type;
  return *this;
}

RsaSsaPkcs1Parameters::Builder& RsaSsaPkcs1Parameters::Builder::SetVariant(
    Variant variant) {
  variant_ = variant;
  return *this;
}

util::StatusOr<RsaSsaPkcs1Parameters> RsaSsaPkcs1Parameters::Builder::Build() {
  if (!modulus_size_in_bits_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Key size is not set.");
  }

  if (!hash_type_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Hash type is not set.");
  }

  if (!variant_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Variant is not set.");
  }

  // Validate modulus size.
  if (*modulus_size_in_bits_ < 2048) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid key size: must be at least 2048 bits, got ",
                     *modulus_size_in_bits_, " bits."));
  }

  // Validate the public exponent: public exponent needs to be odd, greater than
  // 65536 and (for consistency with BoringSSL), smaller that 32 bits.
  util::Status exponent_status =
      internal::ValidateRsaPublicExponent(public_exponent_.GetValue());
  if (!exponent_status.ok()) {
    return exponent_status;
  }

  // Validate HashType.
  static const std::set<HashType>* supported_hashes = new std::set<HashType>(
      {HashType::kSha256, HashType::kSha384, HashType::kSha512});
  if (supported_hashes->find(*hash_type_) == supported_hashes->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create RsaSsaPkcs1 parameters with unknown HashType.");
  }

  // Validate variant.
  static const std::set<Variant>* supported_variants =
      new std::set<Variant>({Variant::kTink, Variant::kCrunchy,
                             Variant::kLegacy, Variant::kNoPrefix});
  if (supported_variants->find(*variant_) == supported_variants->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create RsaSsaPkcs1 parameters with unknown variant.");
  }
  return RsaSsaPkcs1Parameters(*modulus_size_in_bits_, public_exponent_,
                               *hash_type_, *variant_);
}

bool RsaSsaPkcs1Parameters::operator==(const Parameters& other) const {
  const RsaSsaPkcs1Parameters* that =
      dynamic_cast<const RsaSsaPkcs1Parameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (modulus_size_in_bits_ != that->modulus_size_in_bits_) {
    return false;
  }
  if (public_exponent_ != that->public_exponent_) {
    return false;
  }
  if (hash_type_ != that->hash_type_) {
    return false;
  }
  if (variant_ != that->variant_) {
    return false;
  }
  return true;
}

// Returns the big endian encoded F4 value as a public exponent default.
BigInteger RsaSsaPkcs1Parameters::Builder::CreateDefaultPublicExponent() {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), kF4);

  std::string F4_string =
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).value();
  return BigInteger(F4_string);
}

}  // namespace tink
}  // namespace crypto
