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
#include "absl/strings/string_view.h"
#include "tink/core/key_manager_base.h"
#include "tink/key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/subtle/ed25519_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ed25519.pb.h"
#include "proto/empty.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::Ed25519PrivateKey;
using google::crypto::tink::Empty;
using google::crypto::tink::KeyData;

class Ed25519PrivateKeyFactory
    : public PrivateKeyFactory,
      public KeyFactoryBase<Ed25519PrivateKey, Empty> {
 public:
  Ed25519PrivateKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::ASYMMETRIC_PRIVATE;
  }

  // Returns KeyData proto that contains Ed25519PublicKey
  // extracted from the given serialized_private_key, which must contain
  // Ed25519PrivateKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(absl::string_view serialized_private_key) const override;

 protected:
  StatusOr<std::unique_ptr<Ed25519PrivateKey>> NewKeyFromFormat(
      const Empty& unused) const override;
};

StatusOr<std::unique_ptr<Ed25519PrivateKey>>
Ed25519PrivateKeyFactory::NewKeyFromFormat(const Empty& unused) const {
  auto key = subtle::SubtleUtilBoringSSL::GetNewEd25519Key();

  // Build Ed25519PrivateKey.
  std::unique_ptr<Ed25519PrivateKey> ed25519_private_key(
      new Ed25519PrivateKey());
  ed25519_private_key->set_version(Ed25519SignKeyManager::kVersion);
  ed25519_private_key->set_key_value(key->private_key);

  // Build Ed25519PublicKey.
  auto ed25519_public_key = ed25519_private_key->mutable_public_key();
  ed25519_public_key->set_version(Ed25519SignKeyManager::kVersion);
  ed25519_public_key->set_key_value(key->public_key);

  return absl::implicit_cast<StatusOr<std::unique_ptr<Ed25519PrivateKey>>>(
      std::move(ed25519_private_key));
}

StatusOr<std::unique_ptr<KeyData>> Ed25519PrivateKeyFactory::GetPublicKeyData(
    absl::string_view serialized_private_key) const {
  Ed25519PrivateKey private_key;
  if (!private_key.ParseFromString(std::string(serialized_private_key))) {
    return Status(
        util::error::INVALID_ARGUMENT,
        absl::StrCat("Could not parse the passed string as proto '",
                     Ed25519VerifyKeyManager::static_key_type(), "'."));
    return util::Status::OK;
  }
  auto status = Ed25519SignKeyManager::Validate(private_key);
  if (!status.ok()) return status;
  auto key_data = absl::make_unique<KeyData>();
  key_data->set_type_url(Ed25519VerifyKeyManager::static_key_type());
  key_data->set_value(private_key.public_key().SerializeAsString());
  key_data->set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);
  return std::move(key_data);
}

constexpr uint32_t Ed25519SignKeyManager::kVersion;

Ed25519SignKeyManager::Ed25519SignKeyManager()
    : key_factory_(absl::make_unique<Ed25519PrivateKeyFactory>()) {}

const KeyFactory& Ed25519SignKeyManager::get_key_factory() const {
  return *key_factory_;
}

uint32_t Ed25519SignKeyManager::get_version() const { return kVersion; }

StatusOr<std::unique_ptr<PublicKeySign>>
Ed25519SignKeyManager::GetPrimitiveFromKey(
    const Ed25519PrivateKey& ed25519_private_key) const {
  Status status = Validate(ed25519_private_key);
  if (!status.ok()) return status;

  // BoringSSL expects a 64-byte private key which contains the public key as a
  // suffix.
  std::string sk = ed25519_private_key.key_value() +
              ed25519_private_key.public_key().key_value();

  auto ed25519_result = subtle::Ed25519SignBoringSsl::New(sk);
  if (!ed25519_result.ok()) return ed25519_result.status();

  std::unique_ptr<PublicKeySign> ed25519(ed25519_result.ValueOrDie().release());
  return std::move(ed25519);
}

// static
Status Ed25519SignKeyManager::Validate(const Ed25519PrivateKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;

  if (key.key_value().length() != 32) {
    return Status(util::error::INVALID_ARGUMENT,
                  "The ED25519 private key must be 32-bytes long.");
  }

  return Ed25519VerifyKeyManager::Validate(key.public_key());
}

}  // namespace tink
}  // namespace crypto
