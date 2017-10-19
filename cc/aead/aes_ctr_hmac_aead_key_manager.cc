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

#include "cc/aead/aes_ctr_hmac_aead_key_manager.h"

#include <map>

#include "cc/aead.h"
#include "cc/key_manager.h"
#include "cc/mac.h"
#include "cc/registry.h"
#include "cc/subtle/aes_ctr_boringssl.h"
#include "cc/subtle/encrypt_then_authenticate.h"
#include "cc/subtle/hmac_boringssl.h"
#include "cc/subtle/random.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "cc/util/validation.h"
#include "google/protobuf/message.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::AesCtrHmacAeadKey;
using google::crypto::tink::AesCtrHmacAeadKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using google::protobuf::Message;

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

constexpr char AesCtrHmacAeadKeyManager::kHmacKeyType[];
constexpr char AesCtrHmacAeadKeyManager::kKeyTypePrefix[];
constexpr char AesCtrHmacAeadKeyManager::kKeyType[];

const int kMinKeySizeInBytes = 16;
const int kMinIvSizeInBytes = 12;
const int kMinTagSizeInBytes = 10;

const std::string& AesCtrHmacAeadKeyManager::get_key_type() const {
  return key_type_;
}

uint32_t AesCtrHmacAeadKeyManager::get_version() const { return 0; }

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
  auto aes_ctr_result = AesCtrBoringSsl::New(
      aes_ctr_hmac_aead_key.aes_ctr_key().key_value(),
      aes_ctr_hmac_aead_key.aes_ctr_key().params().iv_size());
  if (!aes_ctr_result.ok()) return aes_ctr_result.status();

  auto hmac_result = Registry::GetPrimitive<Mac>(
      kHmacKeyType, aes_ctr_hmac_aead_key.hmac_key());
  if (!hmac_result.ok()) return hmac_result.status();

  auto cipher_res = EncryptThenAuthenticate::New(
      std::move(aes_ctr_result.ValueOrDie()),
      std::move(hmac_result.ValueOrDie()),
      aes_ctr_hmac_aead_key.hmac_key().params().tag_size());
  if (!cipher_res.ok()) {
    return cipher_res.status();
  }
  return std::move(cipher_res.ValueOrDie());
}

StatusOr<std::unique_ptr<Message>> AesCtrHmacAeadKeyManager::NewKey(
    const KeyTemplate& key_template) const {
  if (!DoesSupport(key_template.type_url())) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_template.type_url().c_str());
  }

  AesCtrHmacAeadKeyFormat key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return ToStatusF(
        util::error::INVALID_ARGUMENT,
        "Could not parse key_template.value as key format '%sFormat'.",
        key_template.type_url().c_str());
  }
  Status status = Validate(key_format);
  if (!status.ok()) return status;

  std::unique_ptr<AesCtrHmacAeadKey> aes_ctr_hmac_aead_key(
      new AesCtrHmacAeadKey());
  aes_ctr_hmac_aead_key->set_version(get_version());

  // Generate AesCtrKey.
  auto aes_ctr_key = aes_ctr_hmac_aead_key->mutable_aes_ctr_key();
  aes_ctr_key->set_version(get_version());
  *(aes_ctr_key->mutable_params()) = key_format.aes_ctr_key_format().params();
  aes_ctr_key->set_key_value(
      Random::GetRandomBytes(key_format.aes_ctr_key_format().key_size()));

  // Generate HmacKey.
  auto hmac_key = aes_ctr_hmac_aead_key->mutable_hmac_key();
  hmac_key->set_version(get_version());
  *(hmac_key->mutable_params()) = key_format.hmac_key_format().params();
  hmac_key->set_key_value(
      Random::GetRandomBytes(key_format.hmac_key_format().key_size()));

  std::unique_ptr<Message> key = std::move(aes_ctr_hmac_aead_key);
  return std::move(key);
}

Status AesCtrHmacAeadKeyManager::Validate(const AesCtrHmacAeadKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
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

Status AesCtrHmacAeadKeyManager::Validate(
    const AesCtrHmacAeadKeyFormat& key_format) const {
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
