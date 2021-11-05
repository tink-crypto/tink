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

#include "tink/hybrid/internal/hpke_private_key_manager.h"

#include "absl/status/status.h"
#include "tink/hybrid/internal/hpke_key_manager_util.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/validation.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeKeyFormat;
using ::google::crypto::tink::HpkePrivateKey;
using ::google::crypto::tink::HpkePublicKey;

void GenerateX25519Key(HpkePublicKey& public_key, HpkePrivateKey& private_key) {
  std::unique_ptr<subtle::SubtleUtilBoringSSL::X25519Key> key =
      subtle::SubtleUtilBoringSSL::GenerateNewX25519Key();
  public_key.set_public_key(key->public_value, X25519_PUBLIC_VALUE_LEN);
  private_key.set_private_key(key->private_key, X25519_PRIVATE_KEY_LEN);
}

}  // namespace

util::Status HpkePrivateKeyManager::ValidateKeyFormat(
    const HpkeKeyFormat& key_format) const {
  if (!key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument, "Missing params.");
  }
  return ValidateParams(key_format.params());
}

util::StatusOr<HpkePrivateKey> HpkePrivateKeyManager::CreateKey(
    const HpkeKeyFormat& key_format) const {
  // Set key metadata.
  HpkePrivateKey private_key;
  private_key.set_version(get_version());
  HpkePublicKey* public_key = private_key.mutable_public_key();
  public_key->set_version(get_version());
  *(public_key->mutable_params()) = key_format.params();
  // Generate key material.
  switch (key_format.params().kem()) {
    case HpkeKem::DHKEM_X25519_HKDF_SHA256:
      GenerateX25519Key(*public_key, private_key);
      break;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported KEM type: ", key_format.params().kem()));
  }
  return private_key;
}

util::StatusOr<HpkePublicKey> HpkePrivateKeyManager::GetPublicKey(
    const HpkePrivateKey& private_key) const {
  return private_key.public_key();
}

util::Status HpkePrivateKeyManager::ValidateKey(
    const HpkePrivateKey& key) const {
  util::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (!key.has_public_key()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing HPKE public key.");
  }
  return ValidateKeyAndVersion(key.public_key(), get_version());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
