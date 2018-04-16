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

#include "tink/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"

#include "tink/aead.h"
#include "tink/hybrid_encrypt.h"
#include "tink/key_manager.h"
#include "tink/registry.h"
#include "tink/hybrid/ecies_aead_hkdf_dem_helper.h"
#include "tink/subtle/ecies_hkdf_sender_kem_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EciesAeadHkdfPublicKey;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;


namespace crypto {
namespace tink {

// static
StatusOr<std::unique_ptr<HybridEncrypt>>
EciesAeadHkdfHybridEncrypt::New(const EciesAeadHkdfPublicKey& recipient_key) {
  Status status = Validate(recipient_key);
  if (!status.ok()) return status;

  auto kem_result = subtle::EciesHkdfSenderKemBoringSsl::New(
      util::Enums::ProtoToSubtle(
          recipient_key.params().kem_params().curve_type()),
      recipient_key.x(), recipient_key.y());
  if (!kem_result.ok()) return kem_result.status();

  auto dem_result = EciesAeadHkdfDemHelper::New(
      recipient_key.params().dem_params().aead_dem());
  if (!dem_result.ok()) return dem_result.status();

  std::unique_ptr<HybridEncrypt> hybrid_encrypt(new EciesAeadHkdfHybridEncrypt(
      recipient_key,
      std::move(kem_result.ValueOrDie()), std::move(dem_result.ValueOrDie())));
  return std::move(hybrid_encrypt);
}

StatusOr<std::string> EciesAeadHkdfHybridEncrypt::Encrypt(
    absl::string_view plaintext,
    absl::string_view context_info) const {
  // Use KEM to get a symmetric key.
  auto kem_key_result = sender_kem_->GenerateKey(
      util::Enums::ProtoToSubtle(
          recipient_key_.params().kem_params().hkdf_hash_type()),
      recipient_key_.params().kem_params().hkdf_salt(),
      context_info,
      dem_helper_->dem_key_size_in_bytes(),
      util::Enums::ProtoToSubtle(
          recipient_key_.params().ec_point_format()));
  if (!kem_key_result.ok()) return kem_key_result.status();
  auto kem_key = std::move(kem_key_result.ValueOrDie());

  // Use the symmetric key to get an AEAD-primitive.
  auto aead_result = dem_helper_->GetAead(kem_key->get_symmetric_key());
  if (!aead_result.ok()) return aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());

  // Do the actual encryption using the AEAD-primitive.
  auto encrypt_result = aead->Encrypt(plaintext, "");  // empty aad
  if (!encrypt_result.ok()) return encrypt_result.status();

  // Prepend AEAD-ciphertext with a KEM component.
  std::string ciphertext = kem_key->get_kem_bytes();
  ciphertext.append(encrypt_result.ValueOrDie());
  return ciphertext;
}

// static
Status EciesAeadHkdfHybridEncrypt::Validate(const EciesAeadHkdfPublicKey& key) {
  if (key.x().empty() || key.y().empty() || !key.has_params()) {
      return Status(util::error::INVALID_ARGUMENT,
          "Invalid EciesAeadHkdfPublicKey: missing required fields.");
  }
  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
