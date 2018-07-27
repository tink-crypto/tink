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

#include "tink/signature/ecdsa_sign_key_manager.h"

#include "absl/strings/string_view.h"
#include "absl/memory/memory.h"
#include "tink/public_key_sign.h"
#include "tink/key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::EcdsaKeyFormat;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EcdsaPublicKey;
using google::crypto::tink::KeyData;
using portable_proto::MessageLite;
using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

class EcdsaPrivateKeyFactory : public PrivateKeyFactory {
 public:
  EcdsaPrivateKeyFactory() {}

  // Generates a new random EcdsaPrivateKey, based on
  // the given 'key_format', which must contain EcdsaKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override;

  // Generates a new random EcdsaPrivateKey, based on
  // the given 'serialized_key_format', which must contain
  // EcdsaKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Generates a new random EcdsaPrivateKey based on
  // the given 'serialized_key_format' (which must contain
  // EcdsaKeyFormat-proto), and wraps it in a KeyData-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;

  // Returns KeyData proto that contains EcdsaPublicKey
  // extracted from the given serialized_private_key, which must contain
  // EcdsaPrivateKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(absl::string_view serialized_private_key) const override;
};

StatusOr<std::unique_ptr<MessageLite>> EcdsaPrivateKeyFactory::NewKey(
    const portable_proto::MessageLite& key_format) const {
  std::string key_format_url =
      std::string(EcdsaSignKeyManager::kKeyTypePrefix) +
      key_format.GetTypeName();
  if (key_format_url != EcdsaSignKeyManager::kKeyFormatUrl) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key format proto '%s' is not supported by this manager.",
                     key_format_url.c_str());
  }
  const EcdsaKeyFormat& ecdsa_key_format =
        reinterpret_cast<const EcdsaKeyFormat&>(key_format);
  Status status = EcdsaVerifyKeyManager::Validate(ecdsa_key_format);
  if (!status.ok()) return status;

  // Generate new EC key.
  auto ec_key_result = subtle::SubtleUtilBoringSSL::GetNewEcKey(
      util::Enums::ProtoToSubtle(ecdsa_key_format.params().curve()));
  if (!ec_key_result.ok()) return ec_key_result.status();
  auto ec_key = ec_key_result.ValueOrDie();

  // Build EcdsaPrivateKey.
  std::unique_ptr<EcdsaPrivateKey> ecdsa_private_key(
      new EcdsaPrivateKey());
  ecdsa_private_key->set_version(EcdsaSignKeyManager::kVersion);
  ecdsa_private_key->set_key_value(ec_key.priv);
  auto ecdsa_public_key = ecdsa_private_key->mutable_public_key();
  ecdsa_public_key->set_version(EcdsaSignKeyManager::kVersion);
  ecdsa_public_key->set_x(ec_key.pub_x);
  ecdsa_public_key->set_y(ec_key.pub_y);
  *(ecdsa_public_key->mutable_params()) = ecdsa_key_format.params();

  std::unique_ptr<MessageLite> key = std::move(ecdsa_private_key);
  return std::move(key);
}

StatusOr<std::unique_ptr<MessageLite>> EcdsaPrivateKeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  EcdsaKeyFormat key_format;
  if (!key_format.ParseFromString(std::string(serialized_key_format))) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Could not parse the passed string as proto '%s'.",
                     EcdsaSignKeyManager::kKeyFormatUrl);
  }
  return NewKey(key_format);
}

StatusOr<std::unique_ptr<KeyData>> EcdsaPrivateKeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  auto new_key_result = NewKey(serialized_key_format);
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = reinterpret_cast<const EcdsaPrivateKey&>(
      *(new_key_result.ValueOrDie()));
  std::unique_ptr<KeyData> key_data(new KeyData());
  key_data->set_type_url(EcdsaSignKeyManager::kKeyType);
  key_data->set_value(new_key.SerializeAsString());
  key_data->set_key_material_type(KeyData::ASYMMETRIC_PRIVATE);
  return std::move(key_data);
}

StatusOr<std::unique_ptr<KeyData>>
EcdsaPrivateKeyFactory::GetPublicKeyData(
    absl::string_view serialized_private_key) const {
  EcdsaPrivateKey private_key;
  if (!private_key.ParseFromString(std::string(serialized_private_key))) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Could not parse the passed string as proto '%s'.",
                     EcdsaVerifyKeyManager::kKeyType);
  }
  auto status = EcdsaSignKeyManager::Validate(private_key);
  if (!status.ok()) return status;
  auto key_data = absl::make_unique<KeyData>();
  key_data->set_type_url(EcdsaVerifyKeyManager::kKeyType);
  key_data->set_value(private_key.public_key().SerializeAsString());
  key_data->set_key_material_type(KeyData:: ASYMMETRIC_PUBLIC);
  return std::move(key_data);
}

constexpr char EcdsaSignKeyManager::kKeyFormatUrl[];
constexpr char EcdsaSignKeyManager::kKeyTypePrefix[];
constexpr char EcdsaSignKeyManager::kKeyType[];
constexpr uint32_t EcdsaSignKeyManager::kVersion;

EcdsaSignKeyManager::EcdsaSignKeyManager()
    : key_type_(kKeyType), key_factory_(new EcdsaPrivateKeyFactory()) {
}

const std::string& EcdsaSignKeyManager::get_key_type() const {
  return key_type_;
}

const KeyFactory& EcdsaSignKeyManager::get_key_factory() const {
  return *key_factory_;
}

uint32_t EcdsaSignKeyManager::get_version() const {
  return kVersion;
}

StatusOr<std::unique_ptr<PublicKeySign>>
EcdsaSignKeyManager::GetPrimitive(const KeyData& key_data) const {
  if (DoesSupport(key_data.type_url())) {
    EcdsaPrivateKey ecdsa_private_key;
    if (!ecdsa_private_key.ParseFromString(key_data.value())) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url().c_str());
    }
    return GetPrimitiveImpl(ecdsa_private_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_data.type_url().c_str());
  }
}

StatusOr<std::unique_ptr<PublicKeySign>>
EcdsaSignKeyManager::GetPrimitive(const MessageLite& key) const {
  std::string key_type = std::string(kKeyTypePrefix) + key.GetTypeName();
  if (DoesSupport(key_type)) {
    const EcdsaPrivateKey& ecdsa_private_key =
        reinterpret_cast<const EcdsaPrivateKey&>(key);
    return GetPrimitiveImpl(ecdsa_private_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_type.c_str());
  }
}

StatusOr<std::unique_ptr<PublicKeySign>>
EcdsaSignKeyManager::GetPrimitiveImpl(
    const EcdsaPrivateKey& ecdsa_private_key) const {
  Status status = Validate(ecdsa_private_key);
  if (!status.ok()) return status;
  const EcdsaPublicKey& public_key = ecdsa_private_key.public_key();
  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  ec_key.priv = ecdsa_private_key.key_value();
  auto ecdsa_result = subtle::EcdsaSignBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()));
  if (!ecdsa_result.ok()) return ecdsa_result.status();
  std::unique_ptr<PublicKeySign> ecdsa(ecdsa_result.ValueOrDie().release());
  return std::move(ecdsa);
}

// static
Status EcdsaSignKeyManager::Validate(
    const EcdsaPrivateKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  return EcdsaVerifyKeyManager::Validate(key.public_key().params());
}

}  // namespace tink
}  // namespace crypto
