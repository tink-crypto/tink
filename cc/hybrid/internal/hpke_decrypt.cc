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
#include "tink/hybrid/internal/hpke_context.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::HpkePrivateKey;

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
  return {absl::WrapUnique(new HpkeDecrypt(
      recipient_private_key.public_key().params(),
      util::SecretDataFromStringView(recipient_private_key.private_key())))};
}

util::StatusOr<std::string> HpkeDecrypt::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  util::StatusOr<int32_t> encoding_size =
      internal::HpkeEncapsulatedKeyLength(hpke_params_.kem());
  if (!encoding_size.ok()) return encoding_size.status();

  // Verify that ciphertext length is at least the encapsulated key length.
  if (ciphertext.size() < *encoding_size) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext is too short.");
  }
  absl::string_view encapsulated_key = ciphertext.substr(0, *encoding_size);
  absl::string_view ciphertext_payload = ciphertext.substr(*encoding_size);

  util::StatusOr<internal::HpkeParams> params =
      internal::HpkeParamsProtoToStruct(hpke_params_);
  if (!params.ok()) return params.status();

  util::StatusOr<std::unique_ptr<internal::HpkeContext>> recipient_context =
      internal::HpkeContext::SetupRecipient(*params, recipient_private_key_,
                                            encapsulated_key, context_info);
  if (!recipient_context.ok()) return recipient_context.status();

  return (*recipient_context)->Open(ciphertext_payload, /*associated_data=*/"");
}

}  // namespace tink
}  // namespace crypto
