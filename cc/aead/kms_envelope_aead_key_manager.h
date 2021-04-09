// Copyright 2019 Google LLC
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
#ifndef TINK_AEAD_KMS_ENVELOPE_AEAD_KEY_MANAGER_H_
#define TINK_AEAD_KMS_ENVELOPE_AEAD_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/aead.h"
#include "tink/core/key_type_manager.h"
#include "tink/key_manager.h"
#include "tink/util/constants.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/kms_envelope.pb.h"

namespace crypto {
namespace tink {

class KmsEnvelopeAeadKeyManager
    : public KeyTypeManager<google::crypto::tink::KmsEnvelopeAeadKey,
                            google::crypto::tink::KmsEnvelopeAeadKeyFormat,
                            List<Aead>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
    crypto::tink::util::StatusOr<std::unique_ptr<Aead>> Create(
        const google::crypto::tink::KmsEnvelopeAeadKey& key) const override;
  };

  KmsEnvelopeAeadKeyManager()
      : KeyTypeManager(absl::make_unique<AeadFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::REMOTE;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::KmsEnvelopeAeadKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    return ValidateKeyFormat(key.params());
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::KmsEnvelopeAeadKeyFormat& format)
      const override {
    if (format.kek_uri().empty()) {
      return crypto::tink::util::Status(util::error::INVALID_ARGUMENT,
                                        "Missing kek_uri.");
    }
    return util::OkStatus();
  }

  crypto::tink::util::StatusOr<google::crypto::tink::KmsEnvelopeAeadKey>
  CreateKey(const google::crypto::tink::KmsEnvelopeAeadKeyFormat& key_format)
      const override {
    google::crypto::tink::KmsEnvelopeAeadKey key;
    key.set_version(get_version());
    *(key.mutable_params()) = key_format;
    return key;
  }

  FipsCompatibility FipsStatus() const override {
    return FipsCompatibility::kNotFips;
  }

 private:
  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom,
                   google::crypto::tink::KmsEnvelopeAeadKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_KMS_ENVELOPE_AEAD_KEY_MANAGER_H_
