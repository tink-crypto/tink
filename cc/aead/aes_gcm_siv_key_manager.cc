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

#include "tink/aead/aes_gcm_siv_key_manager.h"

#include "absl/base/casts.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/subtle/aes_gcm_siv_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesGcmSivKey;
using ::google::crypto::tink::AesGcmSivKeyFormat;
using ::google::crypto::tink::KeyData;

class AesGcmSivKeyFactory
    : public KeyFactoryBase<AesGcmSivKey, AesGcmSivKeyFormat> {
 public:
  AesGcmSivKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

 protected:
  StatusOr<std::unique_ptr<AesGcmSivKey>> NewKeyFromFormat(
      const AesGcmSivKeyFormat& aes_gcm_siv_key_format) const override {
    Status status = AesGcmSivKeyManager::Validate(aes_gcm_siv_key_format);
    if (!status.ok()) return status;
    std::unique_ptr<AesGcmSivKey> aes_gcm_siv_key(new AesGcmSivKey());
    aes_gcm_siv_key->set_version(AesGcmSivKeyManager::kVersion);
    aes_gcm_siv_key->set_key_value(
        subtle::Random::GetRandomBytes(aes_gcm_siv_key_format.key_size()));
    return absl::implicit_cast<StatusOr<std::unique_ptr<AesGcmSivKey>>>(
        std::move(aes_gcm_siv_key));
  }
};

constexpr uint32_t AesGcmSivKeyManager::kVersion;

AesGcmSivKeyManager::AesGcmSivKeyManager()
    : key_factory_(absl::make_unique<AesGcmSivKeyFactory>()) {}

uint32_t AesGcmSivKeyManager::get_version() const { return kVersion; }

const KeyFactory& AesGcmSivKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Aead>> AesGcmSivKeyManager::GetPrimitiveFromKey(
    const AesGcmSivKey& aes_gcm_siv_key) const {
  Status status = Validate(aes_gcm_siv_key);
  if (!status.ok()) return status;
  auto aes_gcm_siv_result =
      subtle::AesGcmSivBoringSsl::New(aes_gcm_siv_key.key_value());
  if (!aes_gcm_siv_result.ok()) return aes_gcm_siv_result.status();
  return std::move(aes_gcm_siv_result.ValueOrDie());
}

// static
Status AesGcmSivKeyManager::Validate(const AesGcmSivKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  return ValidateAesKeySize(key.key_value().size());
}

// static
Status AesGcmSivKeyManager::Validate(const AesGcmSivKeyFormat& key_format) {
  return ValidateAesKeySize(key_format.key_size());
}

}  // namespace tink
}  // namespace crypto
