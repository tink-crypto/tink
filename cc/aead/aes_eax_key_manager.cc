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

#include "tink/aead/aes_eax_key_manager.h"

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/subtle/aes_eax_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_eax.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using portable_proto::MessageLite;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

class AesEaxKeyFactory : public KeyFactory {
 public:
  AesEaxKeyFactory() {}

  // Generates a new random AesEaxKey, based on the specified 'key_format',
  // which must contain AesEaxKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override;

  // Generates a new random AesEaxKey, based on the specified
  // 'serialized_key_format', which must contain AesEaxKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Generates a new random AesEaxKey, based on the specified
  // 'serialized_key_format' (which must contain AesEaxKeyFormat-proto),
  // and wraps it in a KeyData-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;
};

StatusOr<std::unique_ptr<MessageLite>> AesEaxKeyFactory::NewKey(
    const portable_proto::MessageLite& key_format) const {
  std::string key_format_url =
      std::string(AesEaxKeyManager::kKeyTypePrefix) + key_format.GetTypeName();
  if (key_format_url != AesEaxKeyManager::kKeyFormatUrl) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key format proto '%s' is not supported by this manager.",
                     key_format_url.c_str());
  }
  const AesEaxKeyFormat& aes_eax_key_format =
        reinterpret_cast<const AesEaxKeyFormat&>(key_format);
  Status status = AesEaxKeyManager::Validate(aes_eax_key_format);
  if (!status.ok()) return status;

  // Generate AesEaxKey.
  std::unique_ptr<AesEaxKey> aes_eax_key(new AesEaxKey());
  aes_eax_key->set_version(AesEaxKeyManager::kVersion);
  aes_eax_key->set_key_value(
      subtle::Random::GetRandomBytes(aes_eax_key_format.key_size()));
  aes_eax_key->mutable_params()
      ->set_iv_size(aes_eax_key_format.params().iv_size());
  std::unique_ptr<MessageLite> key = std::move(aes_eax_key);
  return std::move(key);
}

StatusOr<std::unique_ptr<MessageLite>> AesEaxKeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  AesEaxKeyFormat key_format;
  if (!key_format.ParseFromString(std::string(serialized_key_format))) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Could not parse the passed string as proto '%s'.",
                     AesEaxKeyManager::kKeyFormatUrl);
  }
  return NewKey(key_format);
}

StatusOr<std::unique_ptr<KeyData>> AesEaxKeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  auto new_key_result = NewKey(serialized_key_format);
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = reinterpret_cast<const AesEaxKey&>(
      *(new_key_result.ValueOrDie()));
  std::unique_ptr<KeyData> key_data(new KeyData());
  key_data->set_type_url(AesEaxKeyManager::kKeyType);
  key_data->set_value(new_key.SerializeAsString());
  key_data->set_key_material_type(KeyData::SYMMETRIC);
  return std::move(key_data);
}

constexpr char AesEaxKeyManager::kKeyFormatUrl[];
constexpr char AesEaxKeyManager::kKeyTypePrefix[];
constexpr char AesEaxKeyManager::kKeyType[];
constexpr uint32_t AesEaxKeyManager::kVersion;

AesEaxKeyManager::AesEaxKeyManager()
    : key_type_(kKeyType), key_factory_(new AesEaxKeyFactory()) {}

const std::string& AesEaxKeyManager::get_key_type() const {
  return key_type_;
}

uint32_t AesEaxKeyManager::get_version() const {
  return kVersion;
}

const KeyFactory& AesEaxKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<Aead>>
AesEaxKeyManager::GetPrimitive(const KeyData& key_data) const {
  if (DoesSupport(key_data.type_url())) {
    AesEaxKey aes_eax_key;
    if (!aes_eax_key.ParseFromString(key_data.value())) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url().c_str());
    }
    return GetPrimitiveImpl(aes_eax_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_data.type_url().c_str());
  }
}

StatusOr<std::unique_ptr<Aead>>
AesEaxKeyManager::GetPrimitive(const MessageLite& key) const {
  std::string key_type = std::string(kKeyTypePrefix) + key.GetTypeName();
  if (DoesSupport(key_type)) {
    const AesEaxKey& aes_eax_key = reinterpret_cast<const AesEaxKey&>(key);
    return GetPrimitiveImpl(aes_eax_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_type.c_str());
  }
}

StatusOr<std::unique_ptr<Aead>>
AesEaxKeyManager::GetPrimitiveImpl(const AesEaxKey& aes_eax_key) const {
  Status status = Validate(aes_eax_key);
  if (!status.ok()) return status;
  auto aes_eax_result = subtle::AesEaxBoringSsl::New(
      aes_eax_key.key_value(), aes_eax_key.params().iv_size());
  if (!aes_eax_result.ok()) return aes_eax_result.status();
  return std::move(aes_eax_result.ValueOrDie());
}

// static
Status AesEaxKeyManager::Validate(const AesEaxKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  uint32_t key_size = key.key_value().size();
  if (key_size != 16 && key_size != 32) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesEaxKey: key_value has %d bytes; "
                       "supported sizes: 16 or 32 bytes.", key_size);
  }
  uint32_t iv_size = key.params().iv_size();
  if (iv_size != 12 && iv_size != 16) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesEaxKey: iv_size is %d bytes; "
                       "supported sizes: 12 or 16 bytes.", iv_size);
  }
  return Status::OK;
}

// static
Status AesEaxKeyManager::Validate(const AesEaxKeyFormat& key_format) {
  uint32_t key_size = key_format.key_size();
  if (key_size != 16 && key_size != 32) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesEaxKeyFormat: key_size is %d bytes; "
                       "supported sizes: 16 or 32 bytes.", key_size);
  }
  uint32_t iv_size = key_format.params().iv_size();
  if (iv_size != 12 && iv_size != 16) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid AesEaxKeyFormat: iv_size is %d bytes; "
                       "supported sizes: 12 or 16 bytes.", iv_size);
  }
  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
