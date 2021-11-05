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

#include "tink/hybrid/internal/hpke_encrypt.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/hybrid/internal/hpke_encrypt_boringssl.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::HpkePublicKey;

util::StatusOr<std::unique_ptr<HybridEncrypt>> HpkeEncrypt::New(
    const HpkePublicKey& recipient_public_key) {
  if (recipient_public_key.public_key().empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key is empty.");
  }
  if (!recipient_public_key.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key is missing HPKE parameters.");
  }
  return {absl::WrapUnique(new HpkeEncrypt(recipient_public_key))};
}

util::StatusOr<std::string> HpkeEncrypt::Encrypt(
    absl::string_view plaintext, absl::string_view context_info) const {
  util::StatusOr<std::unique_ptr<internal::HpkeEncryptBoringSsl>>
      sender_context = internal::HpkeEncryptBoringSsl::New(
          recipient_public_key_.params(), recipient_public_key_.public_key(),
          context_info);
  if (!sender_context.ok()) {
    return sender_context.status();
  }
  return (*sender_context)
      ->EncapsulateKeyThenEncrypt(plaintext, /*associated_data=*/"");
}

}  // namespace tink
}  // namespace crypto
