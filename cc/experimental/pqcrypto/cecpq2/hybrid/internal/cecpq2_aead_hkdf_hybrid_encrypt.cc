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

#include "tink/experimental/pqcrypto/cecpq2/hybrid/internal/cecpq2_aead_hkdf_hybrid_encrypt.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/aead.h"
#include "tink/util/enums.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

namespace {

util::Status Validate(
    const google::crypto::tink::Cecpq2AeadHkdfPublicKey& key) {
  if (key.x25519_public_key_x().empty() ||
      key.hrss_public_key_marshalled().empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid Cecpq2AeadHkdfPublicKeyInternal: missing KEM "
                        "required fields.");
  }

  if (key.params().kem_params().curve_type() ==
          google::crypto::tink::EllipticCurveType::CURVE25519 &&
      !key.x25519_public_key_y().empty()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Invalid Cecpq2AeadHkdfPublicKeyInternal: has KEM unexpected field.");
  }

  return util::OkStatus();
}

}  // namespace

// static
util::StatusOr<std::unique_ptr<HybridEncrypt>> Cecpq2AeadHkdfHybridEncrypt::New(
    const google::crypto::tink::Cecpq2AeadHkdfPublicKey& recipient_key) {
  util::Status status = Validate(recipient_key);
  if (!status.ok()) return status;

  util::StatusOr<std::unique_ptr<const subtle::Cecpq2HkdfSenderKemBoringSsl>>
      kem_result = subtle::Cecpq2HkdfSenderKemBoringSsl::New(
          util::Enums::ProtoToSubtle(
              recipient_key.params().kem_params().curve_type()),
          recipient_key.x25519_public_key_x(),
          recipient_key.x25519_public_key_y(),
          recipient_key.hrss_public_key_marshalled());
  if (!kem_result.ok()) return kem_result.status();

  util::StatusOr<std::unique_ptr<const Cecpq2AeadHkdfDemHelper>> dem_result =
      Cecpq2AeadHkdfDemHelper::New(
          recipient_key.params().dem_params().aead_dem());
  if (!dem_result.ok()) return dem_result.status();

  return {absl::WrapUnique(new Cecpq2AeadHkdfHybridEncrypt(
      recipient_key, std::move(kem_result).value(),
      std::move(dem_result).value()))};
}

util::StatusOr<std::string> Cecpq2AeadHkdfHybridEncrypt::Encrypt(
    absl::string_view plaintext, absl::string_view context_info) const {
  // Get the key material size based on the DEM type_url.
  util::StatusOr<uint32_t> key_material_size_or =
      dem_helper_->GetKeyMaterialSize();
  if (!key_material_size_or.ok()) return key_material_size_or.status();
  uint32_t key_material_size = key_material_size_or.value();

  // Use KEM to get a symmetric key
  util::StatusOr<
      std::unique_ptr<const subtle::Cecpq2HkdfSenderKemBoringSsl::KemKey>>
      kem_key_result = sender_kem_->GenerateKey(
          util::Enums::ProtoToSubtle(
              recipient_key_.params().kem_params().hkdf_hash_type()),
          recipient_key_.params().kem_params().hkdf_salt(), context_info,
          key_material_size,
          util::Enums::ProtoToSubtle(
              recipient_key_.params().kem_params().ec_point_format()));
  if (!kem_key_result.ok()) return kem_key_result.status();
  std::unique_ptr<const subtle::Cecpq2HkdfSenderKemBoringSsl::KemKey> kem_key =
      std::move(kem_key_result.value());

  // Use the symmetric key to get an AEAD-primitive
  util::StatusOr<std::unique_ptr<crypto::tink::subtle::AeadOrDaead>>
      aead_or_daead_result =
          dem_helper_->GetAeadOrDaead(kem_key->get_symmetric_key());
  if (!aead_or_daead_result.ok()) return aead_or_daead_result.status();
  std::unique_ptr<crypto::tink::subtle::AeadOrDaead> aead_or_daead =
      std::move(aead_or_daead_result.value());

  // Do the actual encryption using the AEAD-primitive
  util::StatusOr<std::string> encrypt_result =
      aead_or_daead->Encrypt(plaintext, "");  // empty aad
  if (!encrypt_result.ok()) return encrypt_result.status();

  // Prepend AEAD-ciphertext with a KEM component
  std::string ciphertext =
      absl::StrCat(kem_key->get_kem_bytes(), encrypt_result.value());

  return ciphertext;
}

}  // namespace tink
}  // namespace crypto
