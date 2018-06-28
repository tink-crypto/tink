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

#include "tink/mac/hmac_key_manager.h"

#include <map>

#include "absl/strings/string_view.h"
#include "tink/mac.h"
#include "tink/key_manager.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::HashType;
using google::crypto::tink::HmacKey;
using google::crypto::tink::HmacKeyFormat;
using google::crypto::tink::HmacParams;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using portable_proto::MessageLite;
using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

class HmacKeyFactory : public KeyFactory {
 public:
  HmacKeyFactory() {}

  // Generates a new random HmacKey, based on the specified 'key_format',
  // which must contain HmacKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override;


  // Generates a new random HmacKey, based on the specified
  // 'serialized_key_format', which must contain HmacKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Generates a new random HmacKey, based on the specified
  // 'serialized_key_format' (which must contain HmacKeyFormat-proto),
  // and wraps it in a KeyData-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;
};

StatusOr<std::unique_ptr<MessageLite>> HmacKeyFactory::NewKey(
    const portable_proto::MessageLite& key_format) const {
  std::string key_format_url =
      std::string(HmacKeyManager::kKeyTypePrefix) + key_format.GetTypeName();
  if (key_format_url != HmacKeyManager::kKeyFormatUrl) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key format proto '%s' is not supported by this manager.",
                     key_format_url.c_str());
  }
  const HmacKeyFormat& hmac_key_format =
      reinterpret_cast<const HmacKeyFormat&>(key_format);
  Status status =  HmacKeyManager::Validate(hmac_key_format);
  if (!status.ok()) return status;

  // Generate HmacKey.
  std::unique_ptr<HmacKey> hmac_key(new HmacKey());
  hmac_key->set_version(HmacKeyManager::kVersion);
  *(hmac_key->mutable_params()) = hmac_key_format.params();
  hmac_key->set_key_value(
      subtle::Random::GetRandomBytes(hmac_key_format.key_size()));
  std::unique_ptr<MessageLite> key = std::move(hmac_key);
  return std::move(key);
}

StatusOr<std::unique_ptr<MessageLite>> HmacKeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  HmacKeyFormat key_format;
  if (!key_format.ParseFromString(std::string(serialized_key_format))) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Could not parse the passed string as proto '%s'.",
                     HmacKeyManager::kKeyFormatUrl);
  }
  return NewKey(key_format);
}

StatusOr<std::unique_ptr<KeyData>> HmacKeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  auto new_key_result = NewKey(serialized_key_format);
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = reinterpret_cast<const HmacKey&>(
      *(new_key_result.ValueOrDie()));
  std::unique_ptr<KeyData> key_data(new KeyData());
  key_data->set_type_url(HmacKeyManager::kKeyType);
  key_data->set_value(new_key.SerializeAsString());
  key_data->set_key_material_type(KeyData::SYMMETRIC);
  return std::move(key_data);
}

constexpr char HmacKeyManager::kKeyFormatUrl[];
constexpr char HmacKeyManager::kKeyTypePrefix[];
constexpr char HmacKeyManager::kKeyType[];
constexpr uint32_t HmacKeyManager::kVersion;

const int kMinKeySizeInBytes = 16;
const int kMinTagSizeInBytes = 10;

HmacKeyManager::HmacKeyManager()
    : key_type_(kKeyType), key_factory_(new HmacKeyFactory()) {}

const std::string& HmacKeyManager::get_key_type() const {
  return key_type_;
}

uint32_t HmacKeyManager::get_version() const {
  return kVersion;
}

const KeyFactory& HmacKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Mac>>
HmacKeyManager::GetPrimitive(const KeyData& key_data) const {
  if (DoesSupport(key_data.type_url())) {
    HmacKey hmac_key;
    if (!hmac_key.ParseFromString(key_data.value())) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url().c_str());
    }
    return GetPrimitiveImpl(hmac_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_data.type_url().c_str());
  }
}

StatusOr<std::unique_ptr<Mac>>
HmacKeyManager::GetPrimitive(const MessageLite& key) const {
  std::string key_type = std::string(kKeyTypePrefix) + key.GetTypeName();
  if (DoesSupport(key_type)) {
    const HmacKey& hmac_key = reinterpret_cast<const HmacKey&>(key);
    return GetPrimitiveImpl(hmac_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_type.c_str());
  }
}

StatusOr<std::unique_ptr<Mac>>
HmacKeyManager::GetPrimitiveImpl(const HmacKey& hmac_key) const {
  Status status = Validate(hmac_key);
  if (!status.ok()) return status;
  auto hmac_result = subtle::HmacBoringSsl::New(
      util::Enums::ProtoToSubtle(hmac_key.params().hash()),
      hmac_key.params().tag_size(),
      hmac_key.key_value());
  if (!hmac_result.ok()) return hmac_result.status();
  return std::move(hmac_result.ValueOrDie());
}

// static
Status HmacKeyManager::Validate(const HmacParams& params) {
  if (params.tag_size() < kMinTagSizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid HmacParams: tag_size %d is too small.",
                     params.tag_size());
  }
  std::map<HashType, uint32_t> max_tag_size = {{HashType::SHA1, 20},
                                               {HashType::SHA256, 32},
                                               {HashType::SHA512, 64}};
  if (max_tag_size.find(params.hash()) == max_tag_size.end()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid HmacParams: HashType '%s' not supported.",
                     Enums::HashName(params.hash()));
  } else {
    if (params.tag_size() > max_tag_size[params.hash()]) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
          "Invalid HmacParams: tag_size %d is too big for HashType '%s'.",
          params.tag_size(), Enums::HashName(params.hash()));
    }
  }
  return Status::OK;
}

// static
Status HmacKeyManager::Validate(const HmacKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  if (key.key_value().size() < kMinKeySizeInBytes) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid HmacKey: key_value is too short.");
  }
  return Validate(key.params());
}

// static
Status HmacKeyManager::Validate(const HmacKeyFormat& key_format) {
  if (key_format.key_size() < kMinKeySizeInBytes) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid HmacKeyFormat: key_size is too small.");
  }
  return Validate(key_format.params());
}

}  // namespace tink
}  // namespace crypto
