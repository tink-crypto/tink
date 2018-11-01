// Copyright 2017 Google Inc.
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

#include "tink/aead/aes_gcm_key_manager.h"

#include "absl/base/casts.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::KeyData;

class AesGcmKeyFactory : public KeyFactoryBase<AesGcmKey, AesGcmKeyFormat> {
 public:
  AesGcmKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

 protected:
  StatusOr<std::unique_ptr<AesGcmKey>> NewKeyFromFormat(
      const AesGcmKeyFormat& aes_gcm_key_format) const override {
    Status status = AesGcmKeyManager::Validate(aes_gcm_key_format);
    if (!status.ok()) return status;
    std::unique_ptr<AesGcmKey> aes_gcm_key(new AesGcmKey());
    aes_gcm_key->set_version(AesGcmKeyManager::kVersion);
    aes_gcm_key->set_key_value(
        subtle::Random::GetRandomBytes(aes_gcm_key_format.key_size()));
    return absl::implicit_cast<StatusOr<std::unique_ptr<AesGcmKey>>>(
        std::move(aes_gcm_key));
  }
};

constexpr uint32_t AesGcmKeyManager::kVersion;

const int kMinKeySizeInBytes = 16;

AesGcmKeyManager::AesGcmKeyManager()
    : key_factory_(absl::make_unique<AesGcmKeyFactory>()) {}

uint32_t AesGcmKeyManager::get_version() const {
  return kVersion;
}

const KeyFactory& AesGcmKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Aead>> AesGcmKeyManager::GetPrimitiveFromKey(
    const AesGcmKey& aes_gcm_key) const {
  Status status = Validate(aes_gcm_key);
  if (!status.ok()) return status;
  auto aes_gcm_result = subtle::AesGcmBoringSsl::New(aes_gcm_key.key_value());
  if (!aes_gcm_result.ok()) return aes_gcm_result.status();
  return std::move(aes_gcm_result.ValueOrDie());
}

// static
Status AesGcmKeyManager::Validate(const AesGcmKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  return ValidateAesKeySize(key.key_value().size());
}

// static
Status AesGcmKeyManager::Validate(const AesGcmKeyFormat& key_format) {
  return ValidateAesKeySize(key_format.key_size());
}

}  // namespace tink
}  // namespace crypto
