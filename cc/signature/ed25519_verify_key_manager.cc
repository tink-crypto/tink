// Copyright 2019 Google Inc.
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

#include "tink/signature/ed25519_verify_key_manager.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/ed25519_verify_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ed25519.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::Ed25519PublicKey;

StatusOr<std::unique_ptr<PublicKeyVerify>>
Ed25519VerifyKeyManager::PublicKeyVerifyFactory::Create(
    const Ed25519PublicKey& public_key) const {
  return subtle::Ed25519VerifyBoringSsl::New(public_key.key_value());
}

Status Ed25519VerifyKeyManager::ValidateKey(const Ed25519PublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;

  if (key.key_value().length() != 32) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "The ED25519 public key must be 32-bytes long.");
  }
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
