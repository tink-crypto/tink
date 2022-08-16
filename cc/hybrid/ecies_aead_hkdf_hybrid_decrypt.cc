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

#include "tink/hybrid/ecies_aead_hkdf_hybrid_decrypt.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/hybrid/ecies_aead_hkdf_dem_helper.h"
#include "tink/hybrid_decrypt.h"
#include "tink/internal/ec_util.h"
#include "tink/subtle/ecies_hkdf_recipient_kem_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "proto/ecies_aead_hkdf.pb.h"

using ::google::crypto::tink::EciesAeadHkdfPrivateKey;
using ::google::crypto::tink::EllipticCurveType;

namespace crypto {
namespace tink {

namespace {
util::Status Validate(const EciesAeadHkdfPrivateKey& key) {
  if (!key.has_public_key() || !key.public_key().has_params() ||
      key.public_key().x().empty() || key.key_value().empty()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Invalid EciesAeadHkdfPublicKey: missing required fields.");
  }

  if (key.public_key().params().has_kem_params() &&
      key.public_key().params().kem_params().curve_type() ==
          EllipticCurveType::CURVE25519) {
    if (!key.public_key().y().empty()) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Invalid EciesAeadHkdfPublicKey: has unexpected field.");
    }
  } else if (key.public_key().y().empty()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Invalid EciesAeadHkdfPublicKey: missing required fields.");
  }
  return util::OkStatus();
}
}  // namespace

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>> EciesAeadHkdfHybridDecrypt::New(
    const EciesAeadHkdfPrivateKey& recipient_key) {
  util::Status status = Validate(recipient_key);
  if (!status.ok()) return status;

  auto kem_result = subtle::EciesHkdfRecipientKemBoringSsl::New(
      util::Enums::ProtoToSubtle(
          recipient_key.public_key().params().kem_params().curve_type()),
      util::SecretDataFromStringView(recipient_key.key_value()));
  if (!kem_result.ok()) return kem_result.status();

  auto dem_result = EciesAeadHkdfDemHelper::New(
      recipient_key.public_key().params().dem_params().aead_dem());
  if (!dem_result.ok()) return dem_result.status();

  return {absl::WrapUnique(new EciesAeadHkdfHybridDecrypt(
      recipient_key.public_key().params(), std::move(kem_result).value(),
      std::move(dem_result).value()))};
}

util::StatusOr<std::string> EciesAeadHkdfHybridDecrypt::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  // Extract KEM-bytes from the ciphertext.
  auto header_size_result = internal::EcPointEncodingSizeInBytes(
      util::Enums::ProtoToSubtle(
          recipient_key_params_.kem_params().curve_type()),
      util::Enums::ProtoToSubtle(recipient_key_params_.ec_point_format()));
  if (!header_size_result.ok()) return header_size_result.status();
  auto header_size = header_size_result.value();
  if (ciphertext.size() < header_size) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too short");
  }

  // Use KEM to get a symmetric key.
  auto symmetric_key_result = recipient_kem_->GenerateKey(
      absl::string_view(ciphertext).substr(0, header_size),
      util::Enums::ProtoToSubtle(
          recipient_key_params_.kem_params().hkdf_hash_type()),
      recipient_key_params_.kem_params().hkdf_salt(), context_info,
      dem_helper_->dem_key_size_in_bytes(),
      util::Enums::ProtoToSubtle(recipient_key_params_.ec_point_format()));
  if (!symmetric_key_result.ok()) return symmetric_key_result.status();
  auto symmetric_key = std::move(symmetric_key_result.value());

  // Use the symmetric key to get an AEAD-primitive.
  auto aead_or_daead_result = dem_helper_->GetAeadOrDaead(symmetric_key);
  if (!aead_or_daead_result.ok()) return aead_or_daead_result.status();
  auto aead_or_daead = std::move(aead_or_daead_result.value());

  // Do the actual decryption using the AEAD-primitive.
  auto decrypt_result =
      aead_or_daead->Decrypt(ciphertext.substr(header_size), "");  // empty aad
  if (!decrypt_result.ok()) return decrypt_result.status();

  return decrypt_result.value();
}

}  // namespace tink
}  // namespace crypto
