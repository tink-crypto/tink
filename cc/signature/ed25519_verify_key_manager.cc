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

#include "absl/strings/string_view.h"
#include "tink/key_manager.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/ed25519_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
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

constexpr uint32_t Ed25519VerifyKeyManager::kVersion;

Ed25519VerifyKeyManager::Ed25519VerifyKeyManager()
    : key_factory_(KeyFactory::AlwaysFailingFactory(
          util::Status(util::error::UNIMPLEMENTED,
                       "Operation not supported for public keys, "
                       "please use the Ed25519SignKeyManager."))) {}

const KeyFactory& Ed25519VerifyKeyManager::get_key_factory() const {
  return *key_factory_;
}

uint32_t Ed25519VerifyKeyManager::get_version() const { return kVersion; }

StatusOr<std::unique_ptr<PublicKeyVerify>>
Ed25519VerifyKeyManager::GetPrimitiveFromKey(
    const Ed25519PublicKey& ed25519_public_key) const {
  Status status = Validate(ed25519_public_key);
  if (!status.ok()) return status;

  auto ed25519_result =
      subtle::Ed25519VerifyBoringSsl::New(ed25519_public_key.key_value());
  if (!ed25519_result.ok()) return ed25519_result.status();

  std::unique_ptr<PublicKeyVerify> ed25519(
      ed25519_result.ValueOrDie().release());
  return std::move(ed25519);
}

// static
Status Ed25519VerifyKeyManager::Validate(const Ed25519PublicKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;

  if (key.key_value().length() != 32) {
    return Status(util::error::INVALID_ARGUMENT,
                  "The ED25519 public key must be 32-bytes long.");
  }

  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
