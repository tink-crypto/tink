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

#include "cc/aead/aes_gcm_key_manager.h"

#include <map>

#include "cc/aead.h"
#include "cc/key_manager.h"
#include "cc/subtle/aes_gcm_boringssl.h"
#include "cc/subtle/random.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "cc/util/validation.h"
#include "google/protobuf/message.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::AesGcmParams;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using google::protobuf::Message;
using util::Status;
using util::StatusOr;

namespace crypto {
namespace tink {

constexpr char AesGcmKeyManager::kKeyTypePrefix[];
constexpr char AesGcmKeyManager::kKeyType[];

const int kMinKeySizeInBytes = 16;

const std::string& AesGcmKeyManager::get_key_type() const {
  return key_type_;
}

uint32_t AesGcmKeyManager::get_version() const {
  return 0;
}

StatusOr<std::unique_ptr<Aead>>
AesGcmKeyManager::GetPrimitive(const KeyData& key_data) const {
  if (DoesSupport(key_data.type_url())) {
    AesGcmKey aes_gcm_key;
    if (!aes_gcm_key.ParseFromString(key_data.value())) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url().c_str());
    }
    return GetPrimitiveImpl(aes_gcm_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_data.type_url().c_str());
  }
}

StatusOr<std::unique_ptr<Aead>>
AesGcmKeyManager::GetPrimitive(const Message& key) const {
  std::string key_type =
      std::string(kKeyTypePrefix) + key.GetDescriptor()->full_name();
  if (DoesSupport(key_type)) {
    const AesGcmKey& aes_gcm_key = reinterpret_cast<const AesGcmKey&>(key);
    return GetPrimitiveImpl(aes_gcm_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_type.c_str());
  }
}

StatusOr<std::unique_ptr<Aead>>
AesGcmKeyManager::GetPrimitiveImpl(const AesGcmKey& aes_gcm_key) const {
  Status status = Validate(aes_gcm_key);
  if (!status.ok()) return status;
  auto aes_gcm_result = AesGcmBoringSsl::New(aes_gcm_key.key_value());
  if (!aes_gcm_result.ok()) return aes_gcm_result.status();
  return std::move(aes_gcm_result.ValueOrDie());
}

StatusOr<std::unique_ptr<Message>> AesGcmKeyManager::NewKey(
    const KeyTemplate& key_template) const {
  if (!DoesSupport(key_template.type_url())) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_template.type_url().c_str());
  }

  AesGcmKeyFormat key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
        "Could not parse key_template.value as key format '%sFormat'.",
        key_template.type_url().c_str());
  }
  Status status = Validate(key_format);
  if (!status.ok()) return status;

  std::unique_ptr<AesGcmKey> aes_gcm_key(new AesGcmKey());
  aes_gcm_key->set_version(get_version());
  *(aes_gcm_key->mutable_params()) = key_format.params();
  aes_gcm_key->set_key_value(Random::GetRandomBytes(key_format.key_size()));
  std::unique_ptr<Message> key = std::move(aes_gcm_key);
  return std::move(key);
}

Status AesGcmKeyManager::Validate(const AesGcmParams& params) const {
  return Status::OK;
}

Status AesGcmKeyManager::Validate(const AesGcmKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  uint32_t key_size = key.key_value().size();
  if (key_size < kMinKeySizeInBytes) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesGcmKey: key_value is too short.");
  }
  if (key_size != 16 && key_size != 24 && key_size != 32) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesGcmKey: key_value has %d bytes; "
                       "supported sizes: 16, 24, or 32 bytes.", key_size);
  }
  return Validate(key.params());
}

Status AesGcmKeyManager::Validate(const AesGcmKeyFormat& key_format) const {
  if (key_format.key_size() < kMinKeySizeInBytes) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesGcmKeyFormat: key_size is too small.");
  }
  return Validate(key_format.params());
}

}  // namespace tink
}  // namespace crypto
