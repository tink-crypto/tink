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

#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"

#include "absl/strings/string_view.h"
#include "tink/hybrid_encrypt.h"
#include "tink/key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::EciesAeadHkdfPublicKey;
using google::crypto::tink::EciesAeadHkdfKeyFormat;
using google::crypto::tink::EciesAeadHkdfParams;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::KeyTemplate;
using portable_proto::MessageLite;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

class EciesAeadHkdfPublicKeyFactory : public KeyFactory {
 public:
  EciesAeadHkdfPublicKeyFactory() {}

  // Not implemented for public keys.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override;

  // Not implemented for public keys.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Not implemented for public keys.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;
};

StatusOr<std::unique_ptr<MessageLite>> EciesAeadHkdfPublicKeyFactory::NewKey(
    const portable_proto::MessageLite& key_format) const {
  return util::Status(util::error::UNIMPLEMENTED,
                      "Operation not supported for public keys, "
                      "please use EciesAeadHkdfPrivateKeyManager.");
}

StatusOr<std::unique_ptr<MessageLite>> EciesAeadHkdfPublicKeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  return util::Status(util::error::UNIMPLEMENTED,
                      "Operation not supported for public keys, "
                      "please use EciesAeadHkdfPrivateKeyManager.");
}

StatusOr<std::unique_ptr<KeyData>> EciesAeadHkdfPublicKeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  return util::Status(util::error::UNIMPLEMENTED,
                      "Operation not supported for public keys, "
                      "please use EciesAeadHkdfPrivateKeyManager.");
}

constexpr char EciesAeadHkdfPublicKeyManager::kKeyTypePrefix[];
constexpr char EciesAeadHkdfPublicKeyManager::kKeyType[];
constexpr uint32_t EciesAeadHkdfPublicKeyManager::kVersion;

EciesAeadHkdfPublicKeyManager::EciesAeadHkdfPublicKeyManager()
    : key_type_(kKeyType), key_factory_(new EciesAeadHkdfPublicKeyFactory()) {
}

const KeyFactory& EciesAeadHkdfPublicKeyManager::get_key_factory() const {
  return *key_factory_;
}

const std::string& EciesAeadHkdfPublicKeyManager::get_key_type() const {
  return key_type_;
}

uint32_t EciesAeadHkdfPublicKeyManager::get_version() const {
  return kVersion;
}

StatusOr<std::unique_ptr<HybridEncrypt>>
EciesAeadHkdfPublicKeyManager::GetPrimitive(const KeyData& key_data) const {
  if (DoesSupport(key_data.type_url())) {
    EciesAeadHkdfPublicKey ecies_public_key;
    if (!ecies_public_key.ParseFromString(key_data.value())) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url().c_str());
    }
    return GetPrimitiveImpl(ecies_public_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_data.type_url().c_str());
  }
}

StatusOr<std::unique_ptr<HybridEncrypt>>
EciesAeadHkdfPublicKeyManager::GetPrimitive(const MessageLite& key) const {
  std::string key_type = std::string(kKeyTypePrefix) + key.GetTypeName();
  if (DoesSupport(key_type)) {
    const EciesAeadHkdfPublicKey& ecies_public_key =
        reinterpret_cast<const EciesAeadHkdfPublicKey&>(key);
    return GetPrimitiveImpl(ecies_public_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_type.c_str());
  }
}

StatusOr<std::unique_ptr<HybridEncrypt>>
EciesAeadHkdfPublicKeyManager::GetPrimitiveImpl(
    const EciesAeadHkdfPublicKey& recipient_key) const {
  Status status = Validate(recipient_key);
  if (!status.ok()) return status;
  auto ecies_result = EciesAeadHkdfHybridEncrypt::New(recipient_key);
  if (!ecies_result.ok()) return ecies_result.status();
  return std::move(ecies_result.ValueOrDie());
}

// static
Status EciesAeadHkdfPublicKeyManager::Validate(
    const EciesAeadHkdfParams& params) {
  // Validate KEM params.
  if (!params.has_kem_params()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing kem_params.");
  }
  if (params.kem_params().curve_type() == EllipticCurveType::UNKNOWN_CURVE ||
      params.kem_params().hkdf_hash_type() == HashType::UNKNOWN_HASH) {
    return Status(util::error::INVALID_ARGUMENT, "Invalid kem_params.");
  }

  // Validate DEM params.
  if (!params.has_dem_params()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing dem_params.");
  }
  if (!params.dem_params().has_aead_dem()) {
    return Status(util::error::INVALID_ARGUMENT, "Invalid dem_params.");
  }

  // Validate EC point format.
  if (params.ec_point_format() == EcPointFormat::UNKNOWN_FORMAT) {
    return Status(util::error::INVALID_ARGUMENT, "Unknown EC point format.");
  }
  return Status::OK;
}

// static
Status EciesAeadHkdfPublicKeyManager::Validate(
    const EciesAeadHkdfPublicKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  if (!key.has_params()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing params.");
  }
  return Validate(key.params());
}

// static
Status EciesAeadHkdfPublicKeyManager::Validate(
    const EciesAeadHkdfKeyFormat& key_format) {
  if (!key_format.has_params()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing params.");
  }
  return Validate(key_format.params());
}

}  // namespace tink
}  // namespace crypto
