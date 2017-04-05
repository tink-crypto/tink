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

#include "cc/mac/hmac_key_manager.h"

#include <map>

#include "cc/mac.h"
#include "cc/key_manager.h"
#include "cc/subtle/hmac_boringssl.h"
#include "cc/subtle/random.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "cc/util/validation.h"
#include "google/protobuf/message.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

using google::cloud::crypto::tink::HashType;
using google::cloud::crypto::tink::HmacKey;
using google::cloud::crypto::tink::HmacKeyFormat;
using google::cloud::crypto::tink::HmacParams;
using google::cloud::crypto::tink::KeyData;
using google::cloud::crypto::tink::KeyTemplate;
using google::protobuf::Message;
using util::Status;
using util::StatusOr;

namespace cloud {
namespace crypto {
namespace tink {

constexpr char HmacKeyManager::kKeyTypePrefix[];
constexpr char HmacKeyManager::kKeyType[];

const int kMinKeySizeInBytes = 16;
const int kMinTagSizeInBytes = 10;

const std::string& HmacKeyManager::get_key_type() const {
  return key_type_;
}

int HmacKeyManager::get_version() const {
  return 0;
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
HmacKeyManager::GetPrimitive(const Message& key) const {
  std::string key_type =
      std::string(kKeyTypePrefix) + key.GetDescriptor()->full_name();
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
  auto hmac_result = HmacBoringSsl::New(hmac_key.params().hash(),
                                      hmac_key.params().tag_size(),
                                      hmac_key.key_value());
  if (!hmac_result.ok()) return hmac_result.status();
  return std::move(hmac_result.ValueOrDie());
}

StatusOr<std::unique_ptr<Message>> HmacKeyManager::NewKey(
    const KeyTemplate& key_template) const {
  if (!DoesSupport(key_template.type_url())) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_template.type_url().c_str());
  }

  HmacKeyFormat key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
        "Could not parse key_template.value as key format '%sFormat'.",
        key_template.type_url().c_str());
  }
  Status status = Validate(key_format);
  if (!status.ok()) return status;

  std::unique_ptr<HmacKey> hmac_key(new HmacKey());
  hmac_key->set_version(get_version());
  *(hmac_key->mutable_params()) = key_format.params();
  hmac_key->set_key_value(Random::GetRandomBytes(key_format.key_size()));
  std::unique_ptr<Message> key = std::move(hmac_key);
  return std::move(key);
}

Status HmacKeyManager::Validate(const HmacParams& params) const {
  if (params.tag_size() < kMinTagSizeInBytes) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid HmacParams: tag_size %d is too small.",
                     params.tag_size());
  }
  std::map<HashType, int> max_tag_size = {{HashType::SHA1, 20},
                                          {HashType::SHA256, 32},
                                          {HashType::SHA512, 64}};
  if (max_tag_size.find(params.hash()) == max_tag_size.end()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid HmacParams: HashType '%s' not supported.",
                     HashType_Name(params.hash()).c_str());
  } else {
    if (params.tag_size() > max_tag_size[params.hash()]) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
          "Invalid HmacParams: tag_size %d is too big for HashType '%s'.",
          params.tag_size(), HashType_Name(params.hash()).c_str());
    }
  }
  return Status::OK;
}

Status HmacKeyManager::Validate(const HmacKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().size() < kMinKeySizeInBytes) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid HmacKey: key_value is too short.");
  }
  return Validate(key.params());
}

Status HmacKeyManager::Validate(const HmacKeyFormat& key_format) const {
  if (key_format.key_size() < kMinKeySizeInBytes) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid HmacKeyFormat: key_size is too small.");
  }
  return Validate(key_format.params());
}

}  // namespace tink
}  // namespace crypto
}  // namespace cloud
