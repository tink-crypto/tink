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

#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"

#include <map>

#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/mac.h"
#include "tink/registry.h"
#include "tink/subtle/aes_ctr_boringssl.h"
#include "tink/subtle/encrypt_then_authenticate.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::AesCtrHmacAeadKey;
using google::crypto::tink::AesCtrHmacAeadKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using portable_proto::Message;


namespace crypto {
namespace tink {

class AesCtrHmacAeadKeyFactory : public KeyFactory {
 public:
  // Generates a new random AesCtrHmacAeadKey, based on the specified
  // 'key_format', which must contain AesCtrHmacAeadKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::Message>>
  NewKey(const portable_proto::Message& key_format) const override;

  // Generates a new random AesCtrHmacAeadKey, based on the specified
  // 'serialized_key_format', which must contain AesCtrHmacAeadKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::Message>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Generates a new random AesCtrHmacAeadKey, based on the specified
  // 'serialized_key_format' (which must contain AesCtrHmacAeadKeyFormat-proto),
  // and wraps it in a KeyData-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;
};

StatusOr<std::unique_ptr<Message>> AesCtrHmacAeadKeyFactory::NewKey(
    const portable_proto::Message& key_format) const {
  std::string key_format_url =
      std::string(AesCtrHmacAeadKeyManager::kKeyTypePrefix)
      + key_format.GetDescriptor()->full_name();
  if (key_format_url != AesCtrHmacAeadKeyManager::kKeyFormatUrl) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key format proto '%s' is not supported by this manager.",
                     key_format_url.c_str());
  }
  const AesCtrHmacAeadKeyFormat& aes_ctr_hmac_aead_key_format =
        reinterpret_cast<const AesCtrHmacAeadKeyFormat&>(key_format);
  Status status =
      AesCtrHmacAeadKeyManager::Validate(aes_ctr_hmac_aead_key_format);
  if (!status.ok()) return status;

  std::unique_ptr<AesCtrHmacAeadKey> aes_ctr_hmac_aead_key(
      new AesCtrHmacAeadKey());
  aes_ctr_hmac_aead_key->set_version(AesCtrHmacAeadKeyManager::kVersion);

  // Generate AesCtrKey.
  auto aes_ctr_key = aes_ctr_hmac_aead_key->mutable_aes_ctr_key();
  aes_ctr_key->set_version(AesCtrHmacAeadKeyManager::kVersion);
  *(aes_ctr_key->mutable_params()) =
      aes_ctr_hmac_aead_key_format.aes_ctr_key_format().params();
  aes_ctr_key->set_key_value(subtle::Random::GetRandomBytes(
      aes_ctr_hmac_aead_key_format.aes_ctr_key_format().key_size()));

  // Generate HmacKey.
  auto hmac_key = aes_ctr_hmac_aead_key->mutable_hmac_key();
  hmac_key->set_version(AesCtrHmacAeadKeyManager::kVersion);
  *(hmac_key->mutable_params()) =
      aes_ctr_hmac_aead_key_format.hmac_key_format().params();
  hmac_key->set_key_value(subtle::Random::GetRandomBytes(
      aes_ctr_hmac_aead_key_format.hmac_key_format().key_size()));

  std::unique_ptr<Message> key = std::move(aes_ctr_hmac_aead_key);
  return std::move(key);
}

StatusOr<std::unique_ptr<Message>> AesCtrHmacAeadKeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  AesCtrHmacAeadKeyFormat key_format;
  if (!key_format.ParseFromString(std::string(serialized_key_format))) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Could not parse the passed string as proto '%s'.",
                     AesCtrHmacAeadKeyManager::kKeyFormatUrl);
  }
  return NewKey(key_format);
}

StatusOr<std::unique_ptr<KeyData>> AesCtrHmacAeadKeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  auto new_key_result = NewKey(serialized_key_format);
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = reinterpret_cast<const AesCtrHmacAeadKey&>(
      *(new_key_result.ValueOrDie()));
  std::unique_ptr<KeyData> key_data(new KeyData());
  key_data->set_type_url(AesCtrHmacAeadKeyManager::kKeyType);
  key_data->set_value(new_key.SerializeAsString());
  key_data->set_key_material_type(KeyData::SYMMETRIC);
  return std::move(key_data);
}

constexpr char AesCtrHmacAeadKeyManager::kHmacKeyType[];
constexpr char AesCtrHmacAeadKeyManager::kKeyFormatUrl[];
constexpr char AesCtrHmacAeadKeyManager::kKeyTypePrefix[];
constexpr char AesCtrHmacAeadKeyManager::kKeyType[];
constexpr uint32_t AesCtrHmacAeadKeyManager::kVersion;

const int kMinKeySizeInBytes = 16;
const int kMinIvSizeInBytes = 12;
const int kMinTagSizeInBytes = 10;

AesCtrHmacAeadKeyManager::AesCtrHmacAeadKeyManager()
    : key_type_(kKeyType), key_factory_(new AesCtrHmacAeadKeyFactory()) {}

const std::string& AesCtrHmacAeadKeyManager::get_key_type() const {
  return key_type_;
}

const KeyFactory& AesCtrHmacAeadKeyManager::get_key_factory() const {
  return *key_factory_;
}

uint32_t AesCtrHmacAeadKeyManager::get_version() const {
  return kVersion;
}

StatusOr<std::unique_ptr<Aead>> AesCtrHmacAeadKeyManager::GetPrimitive(
    const KeyData& key_data) const {
  if (DoesSupport(key_data.type_url())) {
    AesCtrHmacAeadKey aes_ctr_hmac_aead_key;
    if (!aes_ctr_hmac_aead_key.ParseFromString(key_data.value())) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url().c_str());
    }
    return GetPrimitiveImpl(aes_ctr_hmac_aead_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_data.type_url().c_str());
  }
}

StatusOr<std::unique_ptr<Aead>> AesCtrHmacAeadKeyManager::GetPrimitive(
    const Message& key) const {
  std::string key_type =
      std::string(kKeyTypePrefix) + key.GetDescriptor()->full_name();
  if (DoesSupport(key_type)) {
    const AesCtrHmacAeadKey& aes_ctr_hmac_aead_key =
        reinterpret_cast<const AesCtrHmacAeadKey&>(key);
    return GetPrimitiveImpl(aes_ctr_hmac_aead_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_type.c_str());
  }
}

StatusOr<std::unique_ptr<Aead>> AesCtrHmacAeadKeyManager::GetPrimitiveImpl(
    const AesCtrHmacAeadKey& aes_ctr_hmac_aead_key) const {
  Status status = Validate(aes_ctr_hmac_aead_key);
  if (!status.ok()) return status;
  auto aes_ctr_result = subtle::AesCtrBoringSsl::New(
      aes_ctr_hmac_aead_key.aes_ctr_key().key_value(),
      aes_ctr_hmac_aead_key.aes_ctr_key().params().iv_size());
  if (!aes_ctr_result.ok()) return aes_ctr_result.status();

  auto hmac_result = Registry::GetPrimitive<Mac>(
      kHmacKeyType, aes_ctr_hmac_aead_key.hmac_key());
  if (!hmac_result.ok()) return hmac_result.status();

  auto cipher_res = subtle::EncryptThenAuthenticate::New(
      std::move(aes_ctr_result.ValueOrDie()),
      std::move(hmac_result.ValueOrDie()),
      aes_ctr_hmac_aead_key.hmac_key().params().tag_size());
  if (!cipher_res.ok()) {
    return cipher_res.status();
  }
  return std::move(cipher_res.ValueOrDie());
}

// static
Status AesCtrHmacAeadKeyManager::Validate(const AesCtrHmacAeadKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;

  // Validate AesCtrKey.
  auto aes_ctr_key = key.aes_ctr_key();
  uint32_t aes_key_size = aes_ctr_key.key_value().size();
  if (aes_key_size < kMinKeySizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesCtrHmacAeadKey: AES key_value is too short.");
  }
  if (aes_key_size != 16 && aes_key_size != 24 && aes_key_size != 32) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesCtrHmacAeadKey: AES key_value has %d bytes; "
                     "supported sizes: 16, 24, or 32 bytes.",
                     aes_key_size);
  }
  if (aes_ctr_key.params().iv_size() < kMinIvSizeInBytes ||
      aes_ctr_key.params().iv_size() > 16) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesCtrHmacAeadKey: IV size out of range.");
  }
  return Status::OK;
}

// static
Status AesCtrHmacAeadKeyManager::Validate(
    const AesCtrHmacAeadKeyFormat& key_format) {
  // Validate AesCtrKeyFormat.
  auto aes_ctr_key_format = key_format.aes_ctr_key_format();
  if (aes_ctr_key_format.key_size() < kMinKeySizeInBytes) {
    return ToStatusF(
        util::error::INVALID_ARGUMENT,
        "Invalid AesCtrHmacAeadKeyFormat: AES key_size is too small.");
  }
  if (aes_ctr_key_format.params().iv_size() < kMinIvSizeInBytes ||
      aes_ctr_key_format.params().iv_size() > 16) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid AesCtrHmacAeadKeyFormat: IV size out of range.");
  }

  // Validate HmacKeyFormat.
  auto hmac_key_format = key_format.hmac_key_format();
  if (aes_ctr_key_format.key_size() < kMinKeySizeInBytes) {
    return ToStatusF(
        util::error::INVALID_ARGUMENT,
        "Invalid AesCtrHmacAeadKeyFormat: HMAC key_size is too small.");
  }
  auto params = hmac_key_format.params();
  if (params.tag_size() < kMinTagSizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid HmacParams: tag_size %d is too small.",
                     params.tag_size());
  }
  std::map<HashType, uint32_t> max_tag_size = {
      {HashType::SHA1, 20}, {HashType::SHA256, 32}, {HashType::SHA512, 64}};
  if (max_tag_size.find(params.hash()) == max_tag_size.end()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid HmacParams: HashType '%s' not supported.",
                     HashType_Name(params.hash()).c_str());
  } else {
    if (params.tag_size() > max_tag_size[params.hash()]) {
      return ToStatusF(
          util::error::INVALID_ARGUMENT,
          "Invalid HmacParams: tag_size %d is too big for HashType '%s'.",
          params.tag_size(), HashType_Name(params.hash()).c_str());
    }
  }

  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
