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
#ifndef TINK_AEAD_XCHACHA20_POLY1305_KEY_MANAGER_H_
#define TINK_AEAD_XCHACHA20_POLY1305_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/aead.h"
#include "tink/core/key_type_manager.h"
#include "tink/subtle/random.h"
#include "tink/subtle/xchacha20_poly1305_boringssl.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {

class XChaCha20Poly1305KeyManager
    : public KeyTypeManager<google::crypto::tink::XChaCha20Poly1305Key,
                            google::crypto::tink::XChaCha20Poly1305KeyFormat,
                            List<Aead>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
    crypto::tink::util::StatusOr<std::unique_ptr<Aead>> Create(
        const google::crypto::tink::XChaCha20Poly1305Key& key) const override {
      return subtle::XChacha20Poly1305BoringSsl::New(
          util::SecretDataFromStringView(key.key_value()));
    }
  };

  XChaCha20Poly1305KeyManager()
      : KeyTypeManager(absl::make_unique<AeadFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::XChaCha20Poly1305Key& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    uint32_t key_size = key.key_value().size();
    if (key.key_value().size() != kKeySizeInBytes) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrCat("Invalid XChaCha20Poly1305Key: key_value has ", key_size,
                       " bytes; supported size: ", kKeySizeInBytes, " bytes."));
    }
    return crypto::tink::util::OkStatus();
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::XChaCha20Poly1305KeyFormat& key_format)
      const override {
    return crypto::tink::util::OkStatus();
  }

  crypto::tink::util::StatusOr<google::crypto::tink::XChaCha20Poly1305Key>
  CreateKey(const google::crypto::tink::XChaCha20Poly1305KeyFormat& key_format)
      const override {
    google::crypto::tink::XChaCha20Poly1305Key result;
    result.set_version(get_version());
    result.set_key_value(subtle::Random::GetRandomBytes(kKeySizeInBytes));
    return result;
  }

  crypto::tink::util::StatusOr<google::crypto::tink::XChaCha20Poly1305Key>
  DeriveKey(const google::crypto::tink::XChaCha20Poly1305KeyFormat& key_format,
            InputStream* input_stream) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key_format.version(), get_version());
    if (!status.ok()) return status;

    crypto::tink::util::StatusOr<std::string> randomness =
        ReadBytesFromStream(kKeySizeInBytes, input_stream);
    if (!randomness.ok()) {
      if (randomness.status().code() == absl::StatusCode::kOutOfRange) {
        return crypto::tink::util::Status(
            crypto::tink::util::error::INVALID_ARGUMENT,
            "Could not get enough pseudorandomness from input stream");
      }
      return randomness.status();
    }
    google::crypto::tink::XChaCha20Poly1305Key key;
    key.set_version(get_version());
    key.set_key_value(randomness.ValueOrDie());
    return key;
  }

 private:
  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom,
                   google::crypto::tink::XChaCha20Poly1305Key().GetTypeName());
  const int kKeySizeInBytes = 32;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_XCHACHA20_POLY1305_KEY_MANAGER_H_
