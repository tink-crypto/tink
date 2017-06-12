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

#include "cc/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"

#include "cc/aead.h"
#include "cc/hybrid_encrypt.h"
#include "cc/key_manager.h"
#include "cc/registry.h"
#include "cc/hybrid/ecies_aead_hkdf_dem_helper.h"
#include "cc/subtle/ecies_hkdf_sender_kem_boringssl.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/aes_gcm.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EciesAeadHkdfPublicKey;
using util::Status;
using util::StatusOr;

namespace crypto {
namespace tink {

// static
StatusOr<std::unique_ptr<HybridEncrypt>>
EciesAeadHkdfHybridEncrypt::New(const EciesAeadHkdfPublicKey& recipient_key) {
  Status status = Validate(recipient_key);
  if (!status.ok()) return status;

  auto kem_result = EciesHkdfSenderKemBoringSsl::New(
      recipient_key.params().kem_params().curve_type(),
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
    google::protobuf::StringPiece plaintext,
    google::protobuf::StringPiece context_info) const {
  // Use KEM to get a symmetric key.
  auto kem_key_result = sender_kem_->GenerateKey(
      recipient_key_.params().kem_params().hkdf_hash_type(),
      recipient_key_.params().kem_params().hkdf_salt(),
      context_info,
      dem_helper_->dem_key_size_in_bytes(),
      recipient_key_.params().ec_point_format());
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
