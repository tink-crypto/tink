// Copyright 2022 Google LLC
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

#include "tink/hybrid/internal/hpke_context.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/internal/hpke_context_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr int kX25519KemEncodingLengthInBytes = 32;

std::string ConcatenatePayload(absl::string_view encapsulated_key,
                               absl::string_view ciphertext) {
  return absl::StrCat(encapsulated_key, ciphertext);
}

util::StatusOr<HpkePayloadView> SplitPayload(const HpkeKem& kem,
                                             absl::string_view payload) {
  if (kem == HpkeKem::kX25519HkdfSha256) {
    return HpkePayloadView(payload.substr(0, kX25519KemEncodingLengthInBytes),
                           payload.substr(kX25519KemEncodingLengthInBytes));
  }
  return util::Status(
      absl::StatusCode::kInvalidArgument,
      absl::StrCat("Unable to split HPKE payload for KEM type ", kem));
}

util::StatusOr<std::unique_ptr<HpkeContext>> HpkeContext::SetupSender(
    const HpkeParams& params, absl::string_view recipient_public_key,
    absl::string_view info) {
  if (recipient_public_key.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key is empty.");
  }
  util::StatusOr<SenderHpkeContextBoringSsl> sender_context =
      HpkeContextBoringSsl::SetupSender(params, recipient_public_key, info);
  if (!sender_context.ok()) {
    return sender_context.status();
  }
  return {absl::WrapUnique(new HpkeContext(
      sender_context->encapsulated_key, std::move(sender_context->context)))};
}

util::StatusOr<std::unique_ptr<HpkeContext>> HpkeContext::SetupRecipient(
    const HpkeParams& params, const util::SecretData& recipient_private_key,
    absl::string_view encapsulated_key, absl::string_view info) {
  if (recipient_private_key.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is empty.");
  }
  if (encapsulated_key.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Encapsulated key is empty.");
  }
  util::StatusOr<std::unique_ptr<HpkeContextBoringSsl>> context =
      HpkeContextBoringSsl::SetupRecipient(params, recipient_private_key,
                                           encapsulated_key, info);
  if (!context.ok()) {
    return context.status();
  }
  return {absl::WrapUnique(
      new HpkeContext(encapsulated_key, *std::move(context)))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
