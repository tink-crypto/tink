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

#include "tink/aead/kms_envelope_aead_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/aead/kms_envelope_aead.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KmsEnvelopeAeadKey;
using ::google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using ::google::crypto::tink::KeyData;

class KmsEnvelopeAeadKeyFactory :
      public KeyFactoryBase<KmsEnvelopeAeadKey, KmsEnvelopeAeadKeyFormat> {
 public:
  KmsEnvelopeAeadKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::REMOTE;
  }

 protected:
  StatusOr<std::unique_ptr<KmsEnvelopeAeadKey>> NewKeyFromFormat(
      const KmsEnvelopeAeadKeyFormat& key_format) const override {
    Status status = KmsEnvelopeAeadKeyManager::Validate(key_format);
    if (!status.ok()) return status;
    auto key = absl::make_unique<KmsEnvelopeAeadKey>();
    key->set_version(KmsEnvelopeAeadKeyManager::kVersion);
    *(key->mutable_params()) = key_format;
    return std::move(key);
  }
};

constexpr uint32_t KmsEnvelopeAeadKeyManager::kVersion;

KmsEnvelopeAeadKeyManager::KmsEnvelopeAeadKeyManager()
    : key_factory_(absl::make_unique<KmsEnvelopeAeadKeyFactory>()) {}

uint32_t KmsEnvelopeAeadKeyManager::get_version() const {
  return kVersion;
}

const KeyFactory& KmsEnvelopeAeadKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Aead>> KmsEnvelopeAeadKeyManager::GetPrimitiveFromKey(
    const KmsEnvelopeAeadKey& key) const {
  Status status = Validate(key);
  if (!status.ok()) return status;
  const auto& kek_uri = key.params().kek_uri();
  auto kms_client_result = KmsClients::Get(kek_uri);
  if (!kms_client_result.ok()) return kms_client_result.status();
  auto aead_result = kms_client_result.ValueOrDie()->GetAead(kek_uri);
  if (!aead_result.ok()) return aead_result.status();
  return KmsEnvelopeAead::New(key.params().dek_template(),
                              std::move(aead_result.ValueOrDie()));
}

// static
Status KmsEnvelopeAeadKeyManager::Validate(const KmsEnvelopeAeadKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  return Validate(key.params());
}

// static
Status KmsEnvelopeAeadKeyManager::Validate(
    const KmsEnvelopeAeadKeyFormat& key_format) {
  if (key_format.kek_uri().empty()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing kek_uri.");
  }
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
