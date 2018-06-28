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

using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using portable_proto::MessageLite;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

class AesGcmKeyFactory : public KeyFactory {
 public:
  AesGcmKeyFactory() {}

  // Generates a new random AesGcmKey, based on the specified 'key_format',
  // which must contain AesGcmKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override;

  // Generates a new random AesGcmKey, based on the specified
  // 'serialized_key_format', which must contain AesGcmKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Generates a new random AesGcmKey, based on the specified
  // 'serialized_key_format' (which must contain AesGcmKeyFormat-proto),
  // and wraps it in a KeyData-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;
};

StatusOr<std::unique_ptr<MessageLite>> AesGcmKeyFactory::NewKey(
    const portable_proto::MessageLite& key_format) const {
  std::string key_format_url =
      std::string(AesGcmKeyManager::kKeyTypePrefix) + key_format.GetTypeName();
  if (key_format_url != AesGcmKeyManager::kKeyFormatUrl) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key format proto '%s' is not supported by this manager.",
                     key_format_url.c_str());
  }
  const AesGcmKeyFormat& aes_gcm_key_format =
        reinterpret_cast<const AesGcmKeyFormat&>(key_format);
  Status status = AesGcmKeyManager::Validate(aes_gcm_key_format);
  if (!status.ok()) return status;

  // Generate AesGcmKey.
  std::unique_ptr<AesGcmKey> aes_gcm_key(new AesGcmKey());
  aes_gcm_key->set_version(AesGcmKeyManager::kVersion);
  aes_gcm_key->set_key_value(
      subtle::Random::GetRandomBytes(aes_gcm_key_format.key_size()));
  std::unique_ptr<MessageLite> key = std::move(aes_gcm_key);
  return std::move(key);
}

StatusOr<std::unique_ptr<MessageLite>> AesGcmKeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  AesGcmKeyFormat key_format;
  if (!key_format.ParseFromString(std::string(serialized_key_format))) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Could not parse the passed string as proto '%s'.",
                     AesGcmKeyManager::kKeyFormatUrl);
  }
  return NewKey(key_format);
}

StatusOr<std::unique_ptr<KeyData>> AesGcmKeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  auto new_key_result = NewKey(serialized_key_format);
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = reinterpret_cast<const AesGcmKey&>(
      *(new_key_result.ValueOrDie()));
  std::unique_ptr<KeyData> key_data(new KeyData());
  key_data->set_type_url(AesGcmKeyManager::kKeyType);
  key_data->set_value(new_key.SerializeAsString());
  key_data->set_key_material_type(KeyData::SYMMETRIC);
  return std::move(key_data);
}

constexpr char AesGcmKeyManager::kKeyFormatUrl[];
constexpr char AesGcmKeyManager::kKeyTypePrefix[];
constexpr char AesGcmKeyManager::kKeyType[];
constexpr uint32_t AesGcmKeyManager::kVersion;

const int kMinKeySizeInBytes = 16;

AesGcmKeyManager::AesGcmKeyManager()
    : key_type_(kKeyType), key_factory_(new AesGcmKeyFactory()) {}

const std::string& AesGcmKeyManager::get_key_type() const {
  return key_type_;
}

uint32_t AesGcmKeyManager::get_version() const {
  return kVersion;
}

const KeyFactory& AesGcmKeyManager::get_key_factory() const {
  return *key_factory_;
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
AesGcmKeyManager::GetPrimitive(const MessageLite& key) const {
  std::string key_type = std::string(kKeyTypePrefix) + key.GetTypeName();
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
  auto aes_gcm_result = subtle::AesGcmBoringSsl::New(aes_gcm_key.key_value());
  if (!aes_gcm_result.ok()) return aes_gcm_result.status();
  return std::move(aes_gcm_result.ValueOrDie());
}

// static
Status AesGcmKeyManager::Validate(const AesGcmKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
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
  return Status::OK;
}

// static
Status AesGcmKeyManager::Validate(const AesGcmKeyFormat& key_format) {
  if (key_format.key_size() < kMinKeySizeInBytes) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesGcmKeyFormat: key_size is too small.");
  }
  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
