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

#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"

#include "absl/strings/string_view.h"
#include "absl/memory/memory.h"
#include "tink/hybrid_decrypt.h"
#include "tink/key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_hybrid_decrypt.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::EciesAeadHkdfPrivateKey;
using google::crypto::tink::EciesAeadHkdfKeyFormat;
using google::crypto::tink::EciesAeadHkdfParams;
using google::crypto::tink::EciesAeadDemParams;
using google::crypto::tink::EciesHkdfKemParams;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using portable_proto::MessageLite;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

class EciesAeadHkdfPrivateKeyFactory : public PrivateKeyFactory {
 public:
  EciesAeadHkdfPrivateKeyFactory() {}

  // Generates a new random EciesAeadHkdfPrivateKey, based on
  // the given 'key_format', which must contain EciesAeadHkdfKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override;

  // Generates a new random EciesAeadHkdfPrivateKey, based on
  // the given 'serialized_key_format', which must contain
  // EciesAeadHkdfKeyFormat-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Generates a new random EciesAeadHkdfPrivateKey based on
  // the given 'serialized_key_format' (which must contain
  // EciesAeadHkdfKeyFormat-proto), and wraps it in a KeyData-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;

  // Returns KeyData proto that contains EciesAeadHkdfPublicKey
  // extracted from the given serialized_private_key, which must contain
  // EciesAeadHkdfPrivateKey-proto.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(absl::string_view serialized_private_key) const override;
};

StatusOr<std::unique_ptr<MessageLite>> EciesAeadHkdfPrivateKeyFactory::NewKey(
    const portable_proto::MessageLite& key_format) const {
  std::string key_format_url =
      std::string(EciesAeadHkdfPrivateKeyManager::kKeyTypePrefix) +
      key_format.GetTypeName();
  if (key_format_url != EciesAeadHkdfPrivateKeyManager::kKeyFormatUrl) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key format proto '%s' is not supported by this manager.",
                     key_format_url.c_str());
  }
  const EciesAeadHkdfKeyFormat& ecies_key_format =
        reinterpret_cast<const EciesAeadHkdfKeyFormat&>(key_format);
  Status status = EciesAeadHkdfPublicKeyManager::Validate(ecies_key_format);
  if (!status.ok()) return status;

  // Generate new EC key.
  const EciesHkdfKemParams& kem_params = ecies_key_format.params().kem_params();
  auto ec_key_result = subtle::SubtleUtilBoringSSL::GetNewEcKey(
      util::Enums::ProtoToSubtle(kem_params.curve_type()));
  if (!ec_key_result.ok()) return ec_key_result.status();
  auto ec_key = ec_key_result.ValueOrDie();

  // Build EciesAeadHkdfPrivateKey.
  std::unique_ptr<EciesAeadHkdfPrivateKey> ecies_private_key(
      new EciesAeadHkdfPrivateKey());
  ecies_private_key->set_version(EciesAeadHkdfPrivateKeyManager::kVersion);
  ecies_private_key->set_key_value(ec_key.priv);
  auto ecies_public_key = ecies_private_key->mutable_public_key();
  ecies_public_key->set_version(EciesAeadHkdfPrivateKeyManager::kVersion);
  ecies_public_key->set_x(ec_key.pub_x);
  ecies_public_key->set_y(ec_key.pub_y);
  *(ecies_public_key->mutable_params()) = ecies_key_format.params();

  std::unique_ptr<MessageLite> key = std::move(ecies_private_key);
  return std::move(key);
}

StatusOr<std::unique_ptr<MessageLite>> EciesAeadHkdfPrivateKeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  EciesAeadHkdfKeyFormat key_format;
  if (!key_format.ParseFromString(std::string(serialized_key_format))) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Could not parse the passed string as proto '%s'.",
                     EciesAeadHkdfPrivateKeyManager::kKeyFormatUrl);
  }
  return NewKey(key_format);
}

StatusOr<std::unique_ptr<KeyData>> EciesAeadHkdfPrivateKeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  auto new_key_result = NewKey(serialized_key_format);
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = reinterpret_cast<const EciesAeadHkdfPrivateKey&>(
      *(new_key_result.ValueOrDie()));
  std::unique_ptr<KeyData> key_data(new KeyData());
  key_data->set_type_url(EciesAeadHkdfPrivateKeyManager::kKeyType);
  key_data->set_value(new_key.SerializeAsString());
  key_data->set_key_material_type(KeyData::ASYMMETRIC_PRIVATE);
  return std::move(key_data);
}

StatusOr<std::unique_ptr<KeyData>>
EciesAeadHkdfPrivateKeyFactory::GetPublicKeyData(
    absl::string_view serialized_private_key) const {
  EciesAeadHkdfPrivateKey private_key;
  if (!private_key.ParseFromString(std::string(serialized_private_key))) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Could not parse the passed string as proto '%s'.",
                     EciesAeadHkdfPrivateKeyManager::kKeyType);
  }
  auto status = EciesAeadHkdfPrivateKeyManager::Validate(private_key);
  if (!status.ok()) return status;
  auto key_data = absl::make_unique<KeyData>();
  key_data->set_type_url(EciesAeadHkdfPublicKeyManager::static_key_type());
  key_data->set_value(private_key.public_key().SerializeAsString());
  key_data->set_key_material_type(KeyData:: ASYMMETRIC_PUBLIC);
  return std::move(key_data);
}

constexpr char EciesAeadHkdfPrivateKeyManager::kKeyFormatUrl[];
constexpr char EciesAeadHkdfPrivateKeyManager::kKeyTypePrefix[];
constexpr char EciesAeadHkdfPrivateKeyManager::kKeyType[];
constexpr uint32_t EciesAeadHkdfPrivateKeyManager::kVersion;

EciesAeadHkdfPrivateKeyManager::EciesAeadHkdfPrivateKeyManager()
    : key_type_(kKeyType), key_factory_(new EciesAeadHkdfPrivateKeyFactory()) {
}

const std::string& EciesAeadHkdfPrivateKeyManager::get_key_type() const {
  return key_type_;
}

const KeyFactory& EciesAeadHkdfPrivateKeyManager::get_key_factory() const {
  return *key_factory_;
}

uint32_t EciesAeadHkdfPrivateKeyManager::get_version() const {
  return kVersion;
}

StatusOr<std::unique_ptr<HybridDecrypt>>
EciesAeadHkdfPrivateKeyManager::GetPrimitiveFromKey(
    const EciesAeadHkdfPrivateKey& ecies_private_key) const {
  Status status = Validate(ecies_private_key);
  if (!status.ok()) return status;
  auto ecies_result = EciesAeadHkdfHybridDecrypt::New(ecies_private_key);
  if (!ecies_result.ok()) return ecies_result.status();
  return std::move(ecies_result.ValueOrDie());
}

// static
Status EciesAeadHkdfPrivateKeyManager::Validate(
    const EciesAeadHkdfPrivateKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  if (!key.has_public_key()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing public_key.");
  }
  return EciesAeadHkdfPublicKeyManager::Validate(key.public_key());
}

}  // namespace tink
}  // namespace crypto
