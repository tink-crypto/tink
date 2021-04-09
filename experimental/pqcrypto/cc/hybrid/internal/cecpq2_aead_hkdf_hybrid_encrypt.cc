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

#include "pqcrypto/cc/hybrid/internal/cecpq2_aead_hkdf_hybrid_encrypt.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/aead.h"
#include "tink/util/enums.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

namespace {

util::Status Validate(const Cecpq2AeadHkdfPublicKeyInternal& key) {
  if (key.x25519_public_key_x.empty() ||
      key.hrss_public_key_marshaled.empty()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Invalid Cecpq2AeadHkdfPublicKeyInternal: missing KEM "
                        "required fields.");
  }

  if (key.params.curve_type == subtle::EllipticCurveType::CURVE25519 &&
      !key.x25519_public_key_y.empty()) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "Invalid Cecpq2AeadHkdfPublicKeyInternal: has KEM unexpected field.");
  }

  return util::Status::OK;
}

}  // namespace

// static
util::StatusOr<std::unique_ptr<HybridEncrypt>> Cecpq2AeadHkdfHybridEncrypt::New(
    const Cecpq2AeadHkdfPublicKeyInternal& recipient_key) {
  util::Status status = Validate(recipient_key);
  if (!status.ok()) return status;

  util::StatusOr<std::unique_ptr<const subtle::Cecpq2HkdfSenderKemBoringSsl>>
      kem_result = subtle::Cecpq2HkdfSenderKemBoringSsl::New(
          recipient_key.params.curve_type, recipient_key.x25519_public_key_x,
          recipient_key.x25519_public_key_y,
          recipient_key.hrss_public_key_marshaled);
  if (!kem_result.ok()) return kem_result.status();

  util::StatusOr<std::unique_ptr<const Cecpq2AeadHkdfDemHelper>> dem_result =
      Cecpq2AeadHkdfDemHelper::New(recipient_key.params.key_template);
  if (!dem_result.ok()) return dem_result.status();

  return {absl::WrapUnique(new Cecpq2AeadHkdfHybridEncrypt(
      recipient_key, std::move(kem_result).ValueOrDie(),
      std::move(dem_result).ValueOrDie()))};
}

util::StatusOr<std::string> Cecpq2AeadHkdfHybridEncrypt::Encrypt(
    absl::string_view plaintext, absl::string_view context_info) const {
  // Get the key material size based on the DEM type_url.
  util::StatusOr<uint32_t> key_material_size_or =
      dem_helper_->GetKeyMaterialSize();
  if (!key_material_size_or.ok()) return key_material_size_or.status();
  uint32_t key_material_size = key_material_size_or.ValueOrDie();

  // Use KEM to get a symmetric key
  util::StatusOr<
      std::unique_ptr<const subtle::Cecpq2HkdfSenderKemBoringSsl::KemKey>>
      kem_key_result = sender_kem_->GenerateKey(
          recipient_key_.params.hash_type, recipient_key_.params.hkdf_salt,
          context_info, key_material_size, recipient_key_.params.point_format);
  if (!kem_key_result.ok()) return kem_key_result.status();
  std::unique_ptr<const subtle::Cecpq2HkdfSenderKemBoringSsl::KemKey> kem_key =
      std::move(kem_key_result.ValueOrDie());

  // Use the symmetric key to get an AEAD-primitive
  util::StatusOr<std::unique_ptr<crypto::tink::subtle::AeadOrDaead>>
      aead_or_daead_result =
          dem_helper_->GetAeadOrDaead(kem_key->get_symmetric_key());
  if (!aead_or_daead_result.ok()) return aead_or_daead_result.status();
  std::unique_ptr<crypto::tink::subtle::AeadOrDaead> aead_or_daead =
      std::move(aead_or_daead_result.ValueOrDie());

  // Do the actual encryption using the AEAD-primitive
  util::StatusOr<std::string> encrypt_result =
      aead_or_daead->Encrypt(plaintext, "");  // empty aad
  if (!encrypt_result.ok()) return encrypt_result.status();

  // Prepend AEAD-ciphertext with a KEM component
  std::string ciphertext =
      absl::StrCat(kem_key->get_kem_bytes(), encrypt_result.ValueOrDie());

  return ciphertext;
}

}  // namespace tink
}  // namespace crypto
