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

#include "tink/hybrid/internal/hpke_decrypt.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/hybrid/internal/hpke_decrypt_boringssl.h"
#include "tink/hybrid/internal/hpke_key_boringssl.h"
#include "tink/internal/ec_util.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::HpkePrivateKey;

util::StatusOr<int32_t> EncodingSize(HpkeKem kem) {
  switch (kem) {
    case HpkeKem::DHKEM_X25519_HKDF_SHA256:
      return internal::EcPointEncodingSizeInBytes(
          subtle::EllipticCurveType::CURVE25519,
          subtle::EcPointFormat::UNCOMPRESSED);
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unable to determine KEM-encoding length for ", kem));
  }
}

}  // namespace

util::StatusOr<std::unique_ptr<HybridDecrypt>> HpkeDecrypt::New(
    const HpkePrivateKey& recipient_private_key) {
  if (recipient_private_key.private_key().empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is empty.");
  }
  if (!recipient_private_key.has_public_key()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is missing public key.");
  }
  if (!recipient_private_key.public_key().has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is missing HPKE parameters.");
  }
  HpkeParams hpke_params = recipient_private_key.public_key().params();
  util::StatusOr<std::unique_ptr<internal::HpkeKeyBoringSsl>> hpke_key =
      internal::HpkeKeyBoringSsl::New(hpke_params.kem(),
                                      recipient_private_key.private_key());
  if (!hpke_key.ok()) {
    return hpke_key.status();
  }
  return {absl::WrapUnique(new HpkeDecrypt(hpke_params, std::move(*hpke_key)))};
}

util::StatusOr<std::string> HpkeDecrypt::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  util::StatusOr<int32_t> encoding_size = EncodingSize(hpke_params_.kem());
  if (!encoding_size.ok()) {
    return encoding_size.status();
  }
  // Verify that ciphertext length is at least the encapsulated key length.
  if (ciphertext.size() < *encoding_size) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext is too short.");
  }
  absl::string_view encapsulated_key = ciphertext.substr(0, *encoding_size);
  absl::string_view ciphertext_payload = ciphertext.substr(*encoding_size);
  util::StatusOr<std::unique_ptr<internal::HpkeDecryptBoringSsl>>
      recipient_context = internal::HpkeDecryptBoringSsl::New(
          hpke_params_, *recipient_private_key_, encapsulated_key,
          context_info);
  if (!recipient_context.ok()) {
    return recipient_context.status();
  }
  return (*recipient_context)
      ->Decrypt(ciphertext_payload, /*associated_data=*/"");
}

}  // namespace tink
}  // namespace crypto
