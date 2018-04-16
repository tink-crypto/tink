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

#include "tink/subtle/ecies_hkdf_recipient_kem_boringssl.h"

#include "absl/memory/memory.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"
#include "openssl/bn.h"
#include "openssl/ec.h"


namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
EciesHkdfRecipientKemBoringSsl::New(
    EllipticCurveType curve, const std::string& priv_key) {
  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve);
  if (!status_or_ec_group.ok()) return status_or_ec_group.status();
  auto recipient_kem =
      absl::WrapUnique(new EciesHkdfRecipientKemBoringSsl(curve, priv_key));
  // TODO(przydatek): consider refactoring SubtleUtilBoringSSL,
  //     so that the saved group can be used for KEM operations.
  recipient_kem->ec_group_.reset(status_or_ec_group.ValueOrDie());
  return std::move(recipient_kem);
}

EciesHkdfRecipientKemBoringSsl::EciesHkdfRecipientKemBoringSsl(
    EllipticCurveType curve, const std::string& priv_key_value)
    : curve_(curve), priv_key_value_(priv_key_value) {}

util::StatusOr<std::string> EciesHkdfRecipientKemBoringSsl::GenerateKey(
    absl::string_view kem_bytes,
    HashType hash,
    absl::string_view hkdf_salt,
    absl::string_view hkdf_info,
    uint32_t key_size_in_bytes,
    EcPointFormat point_format) const {
  auto status_or_ec_point =
      SubtleUtilBoringSSL::EcPointDecode(curve_, point_format, kem_bytes);
  if (!status_or_ec_point.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid KEM bytes: %s",
                     status_or_ec_point.status().error_message().c_str());
  }
  bssl::UniquePtr<EC_POINT> pub_key(status_or_ec_point.ValueOrDie());
  bssl::UniquePtr<BIGNUM> priv_key(
      BN_bin2bn(reinterpret_cast<const unsigned char*>(priv_key_value_.data()),
                priv_key_value_.size(), nullptr));
  auto status_or_string = SubtleUtilBoringSSL::ComputeEcdhSharedSecret(
      curve_, priv_key.get(), pub_key.get());
  if (!status_or_string.ok()) {
    return status_or_string.status();
  }
  std::string shared_secret(status_or_string.ValueOrDie());
  return Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
