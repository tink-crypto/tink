// Copyright 2021 Google LLC
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

#include "experimental/pqcrypto/cecpq2/hybrid/internal/cecpq2_aead_hkdf_hybrid_decrypt.h"

#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "openssl/hrss.h"
#include "openssl/nid.h"
#include "experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_dem_helper.h"
#include "experimental/pqcrypto/cecpq2/subtle/cecpq2_hkdf_recipient_kem_boringssl.h"
#include "tink/hybrid_decrypt.h"
#include "tink/internal/ec_util.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

namespace {
util::Status Validate(
    const google::crypto::tink::Cecpq2AeadHkdfPrivateKey& key) {
  if (key.hrss_private_key_seed().empty() || key.x25519_private_key().empty() ||
      key.public_key().hrss_public_key_marshalled().empty() ||
      key.public_key().x25519_public_key_x().empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid Cecpq2AeadHkdfPrivateKeyInternal: missing KEM "
                        "required fields.");
  }

  if (key.public_key().params().kem_params().curve_type() ==
      google::crypto::tink::EllipticCurveType::CURVE25519) {
    if (!key.public_key().x25519_public_key_y().empty()) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid Cecpq2AeadHkdfPrivateKeyInternal: has KEM "
                          "unexpected field.");
    }

    if (key.public_key().params().kem_params().ec_point_format() !=
        google::crypto::tink::EcPointFormat::COMPRESSED) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "X25519 only supports compressed elliptic curve points.");
    }
  }

  return util::OkStatus();
}
}  // namespace

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>> Cecpq2AeadHkdfHybridDecrypt::New(
    const google::crypto::tink::Cecpq2AeadHkdfPrivateKey& private_key) {
  util::Status status = Validate(private_key);
  if (!status.ok()) return status;

  util::StatusOr<std::unique_ptr<subtle::Cecpq2HkdfRecipientKemBoringSsl>>
      kem_result = subtle::Cecpq2HkdfRecipientKemBoringSsl::New(
          util::Enums::ProtoToSubtle(
              private_key.public_key().params().kem_params().curve_type()),
          util::SecretDataFromStringView(private_key.x25519_private_key()),
          util::SecretDataFromStringView(private_key.hrss_private_key_seed()));
  if (!kem_result.ok()) return kem_result.status();

  util::StatusOr<std::unique_ptr<const Cecpq2AeadHkdfDemHelper>> dem_result =
      Cecpq2AeadHkdfDemHelper::New(
          private_key.public_key().params().dem_params().aead_dem());
  if (!dem_result.ok()) return dem_result.status();

  return {absl::WrapUnique(new Cecpq2AeadHkdfHybridDecrypt(
      private_key.public_key().params(), std::move(kem_result).ValueOrDie(),
      std::move(dem_result).ValueOrDie()))};
}

util::StatusOr<std::string> Cecpq2AeadHkdfHybridDecrypt::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  util::StatusOr<int32_t> cecpq2_header_point_encoding_size =
      internal::EcPointEncodingSizeInBytes(
          util::Enums::ProtoToSubtle(
              recipient_key_params_.kem_params().curve_type()),
          util::Enums::ProtoToSubtle(
              recipient_key_params_.kem_params().ec_point_format()));
  if (!cecpq2_header_point_encoding_size.ok()) {
    return cecpq2_header_point_encoding_size.status();
  }
  int32_t cecpq2_header_size =
      *cecpq2_header_point_encoding_size + HRSS_CIPHERTEXT_BYTES;
  if (ciphertext.size() < cecpq2_header_size) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too short");
  }

  // Get the key material size based on the DEM type_url.
  util::StatusOr<uint32_t> key_material_size_or =
      dem_helper_->GetKeyMaterialSize();
  if (!key_material_size_or.ok()) return key_material_size_or.status();
  uint32_t key_material_size = key_material_size_or.ValueOrDie();

  // Use KEM to get a symmetric key.
  util::StatusOr<util::SecretData> symmetric_key_result =
      recipient_kem_->GenerateKey(
          absl::string_view(ciphertext).substr(0, cecpq2_header_size),
          util::Enums::ProtoToSubtle(
              recipient_key_params_.kem_params().hkdf_hash_type()),
          recipient_key_params_.kem_params().hkdf_salt(), context_info,
          key_material_size,
          util::Enums::ProtoToSubtle(
              recipient_key_params_.kem_params().ec_point_format()));
  if (!symmetric_key_result.ok()) return symmetric_key_result.status();
  util::SecretData symmetric_key = std::move(symmetric_key_result.ValueOrDie());

  // Use the symmetric key to get an AEAD-primitive.
  util::StatusOr<std::unique_ptr<crypto::tink::subtle::AeadOrDaead>>
      aead_or_daead_result = dem_helper_->GetAeadOrDaead(symmetric_key);
  if (!aead_or_daead_result.ok()) return aead_or_daead_result.status();
  std::unique_ptr<crypto::tink::subtle::AeadOrDaead> aead_or_daead =
      std::move(aead_or_daead_result.ValueOrDie());

  // Do the actual decryption using the AEAD-primitive.
  util::StatusOr<std::string> decrypt_result = aead_or_daead->Decrypt(
      ciphertext.substr(cecpq2_header_size), "");  // empty aad
  if (!decrypt_result.ok()) return decrypt_result.status();

  return decrypt_result.ValueOrDie();
}

}  // namespace tink
}  // namespace crypto
