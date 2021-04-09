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

#include "pqcrypto/cc/hybrid/internal/cecpq2_aead_hkdf_hybrid_decrypt.h"

#include <utility>

#include "absl/memory/memory.h"
#include "openssl/hrss.h"
#include "openssl/nid.h"
#include "tink/hybrid_decrypt.h"
#include "tink/subtle/ec_util.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "pqcrypto/cc/hybrid/cecpq2_aead_hkdf_dem_helper.h"
#include "pqcrypto/cc/subtle/cecpq2_hkdf_recipient_kem_boringssl.h"

namespace crypto {
namespace tink {

namespace {
util::Status Validate(const Cecpq2AeadHkdfPrivateKeyInternal& key) {
  if (key.hrss_private_key_seed.empty() || key.x25519_private_key.empty() ||
      key.cecpq2_public_key.hrss_public_key_marshaled.empty() ||
      key.cecpq2_public_key.x25519_public_key_x.empty()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Invalid Cecpq2AeadHkdfPrivateKeyInternal: missing KEM "
                        "required fields.");
  }

  if (key.cecpq2_public_key.params.curve_type ==
      subtle::EllipticCurveType::CURVE25519) {
    if (!key.cecpq2_public_key.x25519_public_key_y.empty()) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "Invalid Cecpq2AeadHkdfPrivateKeyInternal: has KEM "
                          "unexpected field.");
    }

    if (key.cecpq2_public_key.params.point_format !=
        subtle::EcPointFormat::COMPRESSED) {
      return util::Status(
          util::error::INVALID_ARGUMENT,
          "X25519 only supports compressed elliptic curve points.");
    }
  }

  return util::Status::OK;
}
}  // namespace

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>> Cecpq2AeadHkdfHybridDecrypt::New(
    const Cecpq2AeadHkdfPrivateKeyInternal& private_key_internal) {
  util::Status status = Validate(private_key_internal);
  if (!status.ok()) return status;

  util::StatusOr<std::unique_ptr<subtle::Cecpq2HkdfRecipientKemBoringSsl>>
      kem_result = subtle::Cecpq2HkdfRecipientKemBoringSsl::New(
          private_key_internal.cecpq2_public_key.params.curve_type,
          private_key_internal.x25519_private_key,
          private_key_internal.hrss_private_key_seed);
  if (!kem_result.ok()) return kem_result.status();

  util::StatusOr<std::unique_ptr<const Cecpq2AeadHkdfDemHelper>> dem_result =
      Cecpq2AeadHkdfDemHelper::New(
          private_key_internal.cecpq2_public_key.params.key_template);
  if (!dem_result.ok()) return dem_result.status();

  return {absl::WrapUnique(new Cecpq2AeadHkdfHybridDecrypt(
      private_key_internal.cecpq2_public_key.params,
      std::move(kem_result).ValueOrDie(), std::move(dem_result).ValueOrDie()))};
}

util::StatusOr<std::string> Cecpq2AeadHkdfHybridDecrypt::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  util::StatusOr<uint32_t> cecpq2_header_size_result =
      subtle::EcUtil::EncodingSizeInBytes(recipient_key_params_.curve_type,
                                          recipient_key_params_.point_format);
  if (!cecpq2_header_size_result.ok())
    return cecpq2_header_size_result.status();
  uint32_t cecpq2_header_size =
      cecpq2_header_size_result.ValueOrDie() + HRSS_CIPHERTEXT_BYTES;
  if (ciphertext.size() < cecpq2_header_size) {
    return util::Status(util::error::INVALID_ARGUMENT, "ciphertext too short");
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
          recipient_key_params_.hash_type, recipient_key_params_.hkdf_salt,
          context_info, key_material_size, recipient_key_params_.point_format);
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
