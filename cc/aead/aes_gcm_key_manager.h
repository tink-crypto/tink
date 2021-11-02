// Copyright 2017 Google LLC
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
#ifndef TINK_AEAD_AES_GCM_KEY_MANAGER_H_
#define TINK_AEAD_AES_GCM_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/cord_aes_gcm_boringssl.h"
#include "tink/core/key_type_manager.h"
#include "tink/key_manager.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class AesGcmKeyManager
    : public KeyTypeManager<google::crypto::tink::AesGcmKey,
                            google::crypto::tink::AesGcmKeyFormat,
                            List<Aead, CordAead>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
    crypto::tink::util::StatusOr<std::unique_ptr<Aead>> Create(
        const google::crypto::tink::AesGcmKey& key) const override {
      auto aes_gcm_result = subtle::AesGcmBoringSsl::New(
          util::SecretDataFromStringView(key.key_value()));
      if (!aes_gcm_result.ok()) return aes_gcm_result.status();
      return {std::move(aes_gcm_result.ValueOrDie())};
    }
  };
  class CordAeadFactory : public PrimitiveFactory<CordAead> {
    crypto::tink::util::StatusOr<std::unique_ptr<CordAead>> Create(
        const google::crypto::tink::AesGcmKey& key) const override {
      auto cord_aes_gcm_result = crypto::tink::CordAesGcmBoringSsl::New(
          util::SecretDataFromStringView(key.key_value()));
      if (!cord_aes_gcm_result.ok()) return cord_aes_gcm_result.status();
      return {std::move(cord_aes_gcm_result.ValueOrDie())};
    }
  };

  AesGcmKeyManager()
      : KeyTypeManager(absl::make_unique<AesGcmKeyManager::AeadFactory>(),
                       absl::make_unique<AesGcmKeyManager::CordAeadFactory>()) {
  }

  // Returns the version of this key manager.
  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::AesGcmKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    return ValidateAesKeySize(key.key_value().size());
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::AesGcmKeyFormat& key_format) const override {
    return ValidateAesKeySize(key_format.key_size());
  }

  crypto::tink::util::StatusOr<google::crypto::tink::AesGcmKey> CreateKey(
      const google::crypto::tink::AesGcmKeyFormat& key_format) const override {
    google::crypto::tink::AesGcmKey key;
    key.set_version(get_version());
    key.set_key_value(
        crypto::tink::subtle::Random::GetRandomBytes(key_format.key_size()));
    return key;
  }

  crypto::tink::util::StatusOr<google::crypto::tink::AesGcmKey> DeriveKey(
      const google::crypto::tink::AesGcmKeyFormat& key_format,
      InputStream* input_stream) const override {
    crypto::tink::util::Status status =
      ValidateVersion(key_format.version(), get_version());
    if (!status.ok()) return status;

    crypto::tink::util::StatusOr<std::string> randomness =
        ReadBytesFromStream(key_format.key_size(), input_stream);
    if (!randomness.ok()) {
      if (randomness.status().code() == absl::StatusCode::kOutOfRange) {
        return crypto::tink::util::Status(
            absl::StatusCode::kInvalidArgument,
            "Could not get enough pseudorandomness from input stream");
      }
      return randomness.status();
    }
    google::crypto::tink::AesGcmKey key;
    key.set_version(get_version());
    key.set_key_value(randomness.ValueOrDie());
    return key;
  }

  internal::FipsCompatibility FipsStatus() const override {
    return internal::FipsCompatibility::kRequiresBoringCrypto;
  }

 private:
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::AesGcmKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AES_GCM_KEY_MANAGER_H_
