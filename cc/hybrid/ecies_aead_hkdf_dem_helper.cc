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

#include "tink/hybrid/ecies_aead_hkdf_dem_helper.h"

#include <utility>

#include "absl/memory/memory.h"
#include "tink/aead.h"
#include "tink/deterministic_aead.h"
#include "tink/key_manager.h"
#include "tink/registry.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/statusor.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_siv.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::AeadOrDaead;
using ::google::crypto::tink::AesCtrHmacAeadKey;
using ::google::crypto::tink::AesCtrHmacAeadKeyFormat;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::AesSivKey;
using ::google::crypto::tink::AesSivKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::XChaCha20Poly1305Key;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;

// Internal implementaton of the EciesAeadHkdfDemHelper class, paremetrized by
// the Primitive used for data encapsulation (i.e Aead or DeterministicAead).
template <class EncryptionPrimitive>
class EciesAeadHkdfDemHelperImpl : public EciesAeadHkdfDemHelper {
 public:
  static util::StatusOr<std::unique_ptr<const EciesAeadHkdfDemHelper>> New(
      const google::crypto::tink::KeyTemplate& dem_key_template,
      const DemKeyParams& key_params, const std::string& dem_type_url) {
    auto key_manager_or =
        Registry::get_key_manager<EncryptionPrimitive>(dem_type_url);
    if (!key_manager_or.ok()) {
      return ToStatusF(
          absl::StatusCode::kFailedPrecondition,
          "No manager for DEM key type '%s' found in the registry.",
          dem_type_url);
    }
    const KeyManager<EncryptionPrimitive>* key_manager =
        key_manager_or.ValueOrDie();
    return {absl::make_unique<EciesAeadHkdfDemHelperImpl<EncryptionPrimitive>>(
        key_manager, dem_key_template, key_params)};
  }

  EciesAeadHkdfDemHelperImpl(
      const KeyManager<EncryptionPrimitive>* key_manager,
      const google::crypto::tink::KeyTemplate& key_template,
      DemKeyParams key_params)
      : EciesAeadHkdfDemHelper(key_template, key_params),
        key_manager_(key_manager) {}

 protected:
  crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::subtle::AeadOrDaead>>
  GetAeadOrDaead(const util::SecretData& symmetric_key_value) const override {
    if (symmetric_key_value.size() != key_params_.key_size_in_bytes) {
      return util::Status(util::error::INTERNAL,
                          "Wrong length of symmetric key.");
    }
    auto key_or = key_manager_->get_key_factory().NewKey(key_template_.value());
    if (!key_or.ok()) return key_or.status();
    auto key = std::move(key_or).ValueOrDie();
    if (!ReplaceKeyBytes(symmetric_key_value, key.get())) {
      return util::Status(util::error::INTERNAL,
                          "Generation of DEM-key failed.");
    }

    util::StatusOr<std::unique_ptr<EncryptionPrimitive>> primitive_or =
        key_manager_->GetPrimitive(*key);
    ZeroKeyBytes(key.get());

    if (!primitive_or.ok()) return primitive_or.status();
    return absl::make_unique<AeadOrDaead>(std::move(primitive_or.ValueOrDie()));
  }

 private:
  const KeyManager<EncryptionPrimitive>* key_manager_;  // not owned
};

}  // namespace

util::StatusOr<EciesAeadHkdfDemHelper::DemKeyParams>
EciesAeadHkdfDemHelper::GetKeyParams(const KeyTemplate& key_template) {
  const std::string& type_url = key_template.type_url();
  if (type_url == "type.googleapis.com/google.crypto.tink.AesGcmKey") {
    AesGcmKeyFormat key_format;
    if (!key_format.ParseFromString(key_template.value())) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "Invalid AesGcmKeyFormat in DEM key template");
    }
    return {{AES_GCM_KEY, key_format.key_size()}};
  }
  if (type_url == "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey") {
    AesCtrHmacAeadKeyFormat key_format;
    if (!key_format.ParseFromString(key_template.value())) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "Invalid AesCtrHmacKeyFormat in DEM key template");
    }
    uint32_t dem_key_size = key_format.aes_ctr_key_format().key_size() +
                            key_format.hmac_key_format().key_size();
    return {{AES_CTR_HMAC_AEAD_KEY, dem_key_size,
             key_format.aes_ctr_key_format().key_size()}};
  }
  if (type_url ==
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key") {
    if (!XChaCha20Poly1305KeyFormat().ParseFromString(key_template.value())) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "Invalid XChaCha20KeyFormat in DEM key template");
    }
    return {{XCHACHA20_POLY1305_KEY, 32}};
  }
  if (type_url == "type.googleapis.com/google.crypto.tink.AesSivKey") {
    AesSivKeyFormat key_format;

    if (!key_format.ParseFromString(key_template.value())) {
      return util::Status(util::error::INVALID_ARGUMENT,
                          "Invalid AesSiveKeyFormat in DEM key template");
    }
    return {{AES_SIV_KEY, key_format.key_size()}};
  }
  return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Unsupported DEM key type '%s'.", type_url);
}

// static
util::StatusOr<std::unique_ptr<const EciesAeadHkdfDemHelper>>
EciesAeadHkdfDemHelper::New(const KeyTemplate& dem_key_template) {
  auto key_params_or = GetKeyParams(dem_key_template);
  if (!key_params_or.ok()) return key_params_or.status();
  DemKeyParams key_params = key_params_or.ValueOrDie();
  const std::string& dem_type_url = dem_key_template.type_url();

  if (key_params.key_type == AES_SIV_KEY) {
    return EciesAeadHkdfDemHelperImpl<DeterministicAead>::New(
        dem_key_template, key_params, dem_type_url);
  } else {
    return EciesAeadHkdfDemHelperImpl<Aead>::New(dem_key_template, key_params,
                                                 dem_type_url);
  }
}

bool EciesAeadHkdfDemHelper::ReplaceKeyBytes(
    const util::SecretData& key_bytes,
    portable_proto::MessageLite* proto) const {
  switch (key_params_.key_type) {
    case AES_GCM_KEY: {
      AesGcmKey* key = static_cast<AesGcmKey*>(proto);
      key->set_key_value(std::string(util::SecretDataAsStringView(key_bytes)));
      return true;
    }
    case AES_CTR_HMAC_AEAD_KEY: {
      AesCtrHmacAeadKey* key = static_cast<AesCtrHmacAeadKey*>(proto);
      auto aes_ctr_key = key->mutable_aes_ctr_key();
      aes_ctr_key->set_key_value(
          std::string(util::SecretDataAsStringView(key_bytes).substr(
              0, key_params_.aes_ctr_key_size_in_bytes)));
      auto hmac_key = key->mutable_hmac_key();
      hmac_key->set_key_value(
          std::string(util::SecretDataAsStringView(key_bytes).substr(
              key_params_.aes_ctr_key_size_in_bytes)));
      return true;
    }
    case XCHACHA20_POLY1305_KEY: {
      XChaCha20Poly1305Key* key = static_cast<XChaCha20Poly1305Key*>(proto);
      key->set_key_value(std::string(util::SecretDataAsStringView(key_bytes)));
      return true;
    }
    case AES_SIV_KEY: {
      AesSivKey* key = static_cast<AesSivKey*>(proto);
      key->set_key_value(std::string(util::SecretDataAsStringView(key_bytes)));
      return true;
    }
  }
  return false;
}

void EciesAeadHkdfDemHelper::ZeroKeyBytes(
    portable_proto::MessageLite* proto) const {
  switch (key_params_.key_type) {
    case AES_GCM_KEY: {
      AesGcmKey* key = static_cast<AesGcmKey*>(proto);
      std::unique_ptr<std::string> key_value =
          absl::WrapUnique(key->release_key_value());
      util::SafeZeroString(key_value.get());
      break;
    }
    case AES_CTR_HMAC_AEAD_KEY: {
      AesCtrHmacAeadKey* key = static_cast<AesCtrHmacAeadKey*>(proto);
      std::unique_ptr<std::string> aes_ctr_key_value =
          absl::WrapUnique(key->mutable_aes_ctr_key()->release_key_value());
      util::SafeZeroString(aes_ctr_key_value.get());
      std::unique_ptr<std::string> hmac_key_value =
          absl::WrapUnique(key->mutable_hmac_key()->release_key_value());
      util::SafeZeroString(hmac_key_value.get());
      break;
    }
    case XCHACHA20_POLY1305_KEY: {
      XChaCha20Poly1305Key* key = static_cast<XChaCha20Poly1305Key*>(proto);
      std::unique_ptr<std::string> key_value =
          absl::WrapUnique(key->release_key_value());
      util::SafeZeroString(key_value.get());
      break;
    }
    case AES_SIV_KEY: {
      AesSivKey* key = static_cast<AesSivKey*>(proto);
      std::unique_ptr<std::string> key_value =
          absl::WrapUnique(key->release_key_value());
      util::SafeZeroString(key_value.get());
      break;
    }
  }
}

}  // namespace tink
}  // namespace crypto
