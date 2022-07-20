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

#include "tink/signature/ed25519_sign_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/ec_util.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/subtle/ed25519_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ed25519.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::Ed25519KeyFormat;
using ::google::crypto::tink::Ed25519PrivateKey;

StatusOr<Ed25519PrivateKey> Ed25519SignKeyManager::CreateKey(
    const Ed25519KeyFormat& key_format) const {
  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key =
      internal::NewEd25519Key();
  if (!key.ok()) {
    return key.status();
  }

  Ed25519PrivateKey ed25519_private_key;
  ed25519_private_key.set_version(get_version());
  ed25519_private_key.set_key_value((*key)->private_key);

  // Build Ed25519PublicKey.
  auto ed25519_public_key = ed25519_private_key.mutable_public_key();
  ed25519_public_key->set_version(get_version());
  ed25519_public_key->set_key_value((*key)->public_key);

  return ed25519_private_key;
}

StatusOr<std::unique_ptr<PublicKeySign>>
Ed25519SignKeyManager::PublicKeySignFactory::Create(
    const Ed25519PrivateKey& private_key) const {
  // BoringSSL expects a 64-byte private key which contains the public key as a
  // suffix.
  util::SecretData sk = util::SecretDataFromStringView(absl::StrCat(
      private_key.key_value(), private_key.public_key().key_value()));

  return subtle::Ed25519SignBoringSsl::New(sk);
}

Status Ed25519SignKeyManager::ValidateKey(const Ed25519PrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().length() != 32) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "The ED25519 private key must be 32-bytes long.");
  }
  return Ed25519VerifyKeyManager().ValidateKey(key.public_key());
}

StatusOr<Ed25519PrivateKey> Ed25519SignKeyManager::DeriveKey(
    const Ed25519KeyFormat& key_format, InputStream* input_stream) const {
  util::Status status = ValidateVersion(key_format.version(), get_version());
  if (!status.ok()) return status;

  util::StatusOr<util::SecretData> randomness =
      ReadSecretBytesFromStream(kEd25519SecretSeedSize, input_stream);
  if (!randomness.ok()) {
    if (randomness.status().code() == absl::StatusCode::kOutOfRange) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not get enough pseudorandomness from input stream");
    }
    return randomness.status();
  }
  util::StatusOr<std::unique_ptr<internal::Ed25519Key>> key =
      internal::NewEd25519Key(*randomness);

  Ed25519PrivateKey ed25519_private_key;
  ed25519_private_key.set_version(get_version());
  ed25519_private_key.set_key_value((*key)->private_key);

  // Build Ed25519PublicKey.
  auto ed25519_public_key = ed25519_private_key.mutable_public_key();
  ed25519_public_key->set_version(get_version());
  ed25519_public_key->set_key_value((*key)->public_key);

  return ed25519_private_key;
}

Status Ed25519SignKeyManager::ValidateKeyFormat(
    const Ed25519KeyFormat& key_format) const {
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
