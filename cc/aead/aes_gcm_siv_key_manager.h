// Copyright 2019 Google Inc.
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
#ifndef TINK_AEAD_AES_GCM_SIV_KEY_MANAGER_H_
#define TINK_AEAD_AES_GCM_SIV_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/aead.h"
#include "tink/core/key_type_manager.h"
#include "tink/subtle/aes_gcm_siv_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/constants.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_gcm_siv.pb.h"

namespace crypto {
namespace tink {

class AesGcmSivKeyManager
    : public KeyTypeManager<google::crypto::tink::AesGcmSivKey,
                            google::crypto::tink::AesGcmSivKeyFormat,
                            List<Aead>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
    crypto::tink::util::StatusOr<std::unique_ptr<Aead>> Create(
        const google::crypto::tink::AesGcmSivKey& key) const override {
      return subtle::AesGcmSivBoringSsl::New(
          util::SecretDataFromStringView(key.key_value()));
    }
  };

  AesGcmSivKeyManager() : KeyTypeManager(absl::make_unique<AeadFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::AesGcmSivKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    return ValidateAesKeySize(key.key_value().size());
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::AesGcmSivKeyFormat& format) const override {
    return ValidateAesKeySize(format.key_size());
  }

  crypto::tink::util::StatusOr<google::crypto::tink::AesGcmSivKey> CreateKey(
      const google::crypto::tink::AesGcmSivKeyFormat& format)
      const override {
    google::crypto::tink::AesGcmSivKey key;
    key.set_version(get_version());
    key.set_key_value(subtle::Random::GetRandomBytes(format.key_size()));
    return key;
  }

  FipsCompatibility FipsStatus() const override {
    return FipsCompatibility::kNotFips;
  }

 private:
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::AesGcmSivKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AES_GCM_SIV_KEY_MANAGER_H_
