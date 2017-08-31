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

#include "cc/hybrid/ecies_aead_hkdf_hybrid_decrypt.h"

#include "cc/hybrid_decrypt.h"
#include "cc/hybrid/ecies_aead_hkdf_dem_helper.h"
#include "cc/subtle/ec_util.h"
#include "cc/subtle/ecies_hkdf_recipient_kem_boringssl.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EciesAeadHkdfPrivateKey;

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

// static
util::StatusOr<std::unique_ptr<HybridDecrypt>>
EciesAeadHkdfHybridDecrypt::New(const EciesAeadHkdfPrivateKey& recipient_key) {
  util::Status status = Validate(recipient_key);
  if (!status.ok()) return status;

  auto kem_result = EciesHkdfRecipientKemBoringSsl::New(
      recipient_key.public_key().params().kem_params().curve_type(),
      recipient_key.key_value());
  if (!kem_result.ok()) return kem_result.status();

  auto dem_result = EciesAeadHkdfDemHelper::New(
      recipient_key.public_key().params().dem_params().aead_dem());
  if (!dem_result.ok()) return dem_result.status();

  std::unique_ptr<HybridDecrypt> hybrid_decrypt(new EciesAeadHkdfHybridDecrypt(
      recipient_key,
      std::move(kem_result.ValueOrDie()), std::move(dem_result.ValueOrDie())));
  return std::move(hybrid_decrypt);
}

util::StatusOr<std::string> EciesAeadHkdfHybridDecrypt::Decrypt(
    google::protobuf::StringPiece ciphertext,
    google::protobuf::StringPiece context_info) const {
  // Extract KEM-bytes from the ciphertext.
  auto header_size_result = EcUtil::EncodingSizeInBytes(
      recipient_key_.public_key().params().kem_params().curve_type(),
      recipient_key_.public_key().params().ec_point_format());
  if (!header_size_result.ok()) return header_size_result.status();
  auto header_size = header_size_result.ValueOrDie();
  if (ciphertext.size() < header_size) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext too short");
  }
  std::string kem_bytes = std::string(ciphertext.substr(0, header_size));

  // Use KEM to get a symmetric key.
  auto symmetric_key_result = recipient_kem_->GenerateKey(
      kem_bytes,
      recipient_key_.public_key().params().kem_params().hkdf_hash_type(),
      recipient_key_.public_key().params().kem_params().hkdf_salt(),
      context_info,
      dem_helper_->dem_key_size_in_bytes(),
      recipient_key_.public_key().params().ec_point_format());
  if (!symmetric_key_result.ok()) return symmetric_key_result.status();
  auto symmetric_key = std::move(symmetric_key_result.ValueOrDie());

  // Use the symmetric key to get an AEAD-primitive.
  auto aead_result = dem_helper_->GetAead(symmetric_key);
  if (!aead_result.ok()) return aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());

  // Do the actual decryption using the AEAD-primitive.
  auto decrypt_result =
      aead->Decrypt(ciphertext.substr(header_size), "");  // empty aad
  if (!decrypt_result.ok()) return decrypt_result.status();

  return decrypt_result.ValueOrDie();
}

// static
util::Status EciesAeadHkdfHybridDecrypt::Validate(
    const EciesAeadHkdfPrivateKey& key) {
  if (!key.has_public_key() || !key.public_key().has_params()
      || key.public_key().x().empty() || key.public_key().y().empty()
      || key.key_value().empty()) {
    return util::Status(util::error::INVALID_ARGUMENT,
          "Invalid EciesAeadHkdfPublicKey: missing required fields.");
  }
  return util::Status::OK;
}

}  // namespace tink
}  // namespace crypto
