// Copyright 2018 Google Inc.
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
#ifndef TINK_DAEAD_AES_SIV_KEY_MANAGER_H_
#define TINK_DAEAD_AES_SIV_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/deterministic_aead.h"
#include "tink/subtle/aes_siv_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_siv.pb.h"

namespace crypto {
namespace tink {

class AesSivKeyManager
    : public KeyTypeManager<google::crypto::tink::AesSivKey,
                            google::crypto::tink::AesSivKeyFormat,
                            List<DeterministicAead>> {
 public:
  class DeterministicAeadFactory : public PrimitiveFactory<DeterministicAead> {
    crypto::tink::util::StatusOr<std::unique_ptr<DeterministicAead>> Create(
        const google::crypto::tink::AesSivKey& key) const override {
      return subtle::AesSivBoringSsl::New(
          util::SecretDataFromStringView(key.key_value()));
    }
  };

  AesSivKeyManager()
      : KeyTypeManager(absl::make_unique<DeterministicAeadFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::AesSivKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    return ValidateKeySize(key.key_value().size());
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::AesSivKeyFormat& key_format) const override {
    return ValidateKeySize(key_format.key_size());
  }

  crypto::tink::util::StatusOr<google::crypto::tink::AesSivKey> CreateKey(
      const google::crypto::tink::AesSivKeyFormat& key_format) const override {
    google::crypto::tink::AesSivKey key;
    key.set_version(get_version());
    key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
    return key;
  }

  crypto::tink::util::StatusOr<google::crypto::tink::AesSivKey> DeriveKey(
      const google::crypto::tink::AesSivKeyFormat& key_format,
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
    google::crypto::tink::AesSivKey key;
    key.set_version(get_version());
    key.set_key_value(randomness.value());
    return key;
  }

 private:
  crypto::tink::util::Status ValidateKeySize(uint32_t key_size) const {
    if (key_size != kKeySizeInBytes) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid key size: key size is ", key_size,
                       " bytes; supported size: ", kKeySizeInBytes, " bytes."));
    }
    return crypto::tink::util::OkStatus();
  }

  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::AesSivKey().GetTypeName());
  const int kKeySizeInBytes = 64;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_AES_SIV_KEY_MANAGER_H_
