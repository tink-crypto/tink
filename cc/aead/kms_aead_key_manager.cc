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

#include "tink/aead/kms_aead_key_manager.h"

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/kms_aead.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KmsAeadKey;
using ::google::crypto::tink::KmsAeadKeyFormat;
using ::google::crypto::tink::KeyData;

class KmsAeadKeyFactory : public KeyFactoryBase<KmsAeadKey, KmsAeadKeyFormat> {
 public:
  KmsAeadKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::REMOTE;
  }

 protected:
  StatusOr<std::unique_ptr<KmsAeadKey>> NewKeyFromFormat(
      const KmsAeadKeyFormat& kms_aead_key_format) const override {
    Status status = KmsAeadKeyManager::Validate(kms_aead_key_format);
    if (!status.ok()) return status;
    std::unique_ptr<KmsAeadKey> kms_aead_key(new KmsAeadKey());
    kms_aead_key->set_version(KmsAeadKeyManager::kVersion);
    *(kms_aead_key->mutable_params()) = kms_aead_key_format;
    return std::move(kms_aead_key);
  }
};

constexpr uint32_t KmsAeadKeyManager::kVersion;

KmsAeadKeyManager::KmsAeadKeyManager()
    : key_factory_(absl::make_unique<KmsAeadKeyFactory>()) {}

uint32_t KmsAeadKeyManager::get_version() const {
  return kVersion;
}

const KeyFactory& KmsAeadKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Aead>> KmsAeadKeyManager::GetPrimitiveFromKey(
    const KmsAeadKey& kms_aead_key) const {
  Status status = Validate(kms_aead_key);
  if (!status.ok()) return status;
  const auto& key_uri = kms_aead_key.params().key_uri();
  auto kms_client_result = KmsClients::Get(key_uri);
  if (!kms_client_result.ok()) return kms_client_result.status();
  return kms_client_result.ValueOrDie()->GetAead(key_uri);
}

// static
Status KmsAeadKeyManager::Validate(const KmsAeadKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  return Validate(key.params());
}

// static
Status KmsAeadKeyManager::Validate(const KmsAeadKeyFormat& key_format) {
  if (key_format.key_uri().empty()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing key_uri.");
  }
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
