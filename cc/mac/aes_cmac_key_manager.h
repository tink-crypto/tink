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
#ifndef TINK_MAC_AES_CMAC_KEY_MANAGER_H_
#define TINK_MAC_AES_CMAC_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/chunked_mac.h"
#include "tink/core/key_type_manager.h"
#include "tink/key_manager.h"
#include "tink/mac.h"
#include "tink/mac/internal/chunked_mac_impl.h"
#include "tink/subtle/aes_cmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_cmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class AesCmacKeyManager
    : public KeyTypeManager<google::crypto::tink::AesCmacKey,
                            google::crypto::tink::AesCmacKeyFormat,
                            List<Mac, ChunkedMac>> {
 public:
  class MacFactory : public PrimitiveFactory<Mac> {
    crypto::tink::util::StatusOr<std::unique_ptr<Mac>> Create(
        const google::crypto::tink::AesCmacKey& key) const override {
      return subtle::AesCmacBoringSsl::New(
          util::SecretDataFromStringView(key.key_value()),
          key.params().tag_size());
    }
  };

  class ChunkedMacFactory : public PrimitiveFactory<ChunkedMac> {
    crypto::tink::util::StatusOr<std::unique_ptr<ChunkedMac>> Create(
        const google::crypto::tink::AesCmacKey& key) const override {
      return internal::NewChunkedCmac(key);
    }
  };

  AesCmacKeyManager()
      : KeyTypeManager(
            absl::make_unique<AesCmacKeyManager::MacFactory>(),
            absl::make_unique<AesCmacKeyManager::ChunkedMacFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::AesCmacKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    if (key.key_value().size() != kKeySizeInBytes) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          "Invalid AesCmacKey: key_value wrong length.");
    }
    return ValidateParams(key.params());
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::AesCmacKeyFormat& key_format) const override {
    if (key_format.key_size() != kKeySizeInBytes) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          "Invalid AesCmacKeyFormat: invalid key_size.");
    }
    return ValidateParams(key_format.params());
  }

  crypto::tink::util::StatusOr<google::crypto::tink::AesCmacKey> CreateKey(
      const google::crypto::tink::AesCmacKeyFormat& key_format) const override {
    google::crypto::tink::AesCmacKey key;
    key.set_version(get_version());
    key.set_key_value(
        subtle::Random::GetRandomBytes(key_format.key_size()));
    *key.mutable_params() = key_format.params();
    return key;
  }

 private:
  crypto::tink::util::Status ValidateParams(
      const google::crypto::tink::AesCmacParams& params) const {
    if (params.tag_size() < kMinTagSizeInBytes) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Invalid AesCmacParams: tag_size ",
                                       params.tag_size(), " is too small."));
    }
    if (params.tag_size() > kMaxTagSizeInBytes) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Invalid AesCmacParams: tag_size ",
                                       params.tag_size(), " is too big."));
    }
    return util::OkStatus();
  }

  // Due to https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf,
  // we only allow key sizes of 256 bit.
  const int kKeySizeInBytes = 32;
  const int kMaxTagSizeInBytes = 16;
  const int kMinTagSizeInBytes = 10;

  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::AesCmacKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_AES_CMAC_KEY_MANAGER_H_
