// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_PRF_HKDF_PRF_KEY_MANAGER_H_
#define TINK_PRF_HKDF_PRF_KEY_MANAGER_H_

#include <string>

#include "tink/core/key_type_manager.h"
#include "tink/subtle/prf/hkdf_streaming_prf.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/subtle/random.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class HkdfPrfKeyManager
    : public KeyTypeManager<google::crypto::tink::HkdfPrfKey,
                            google::crypto::tink::HkdfPrfKeyFormat,
                            List<StreamingPrf>> {
 public:
  class StreamingPrfFactory : public PrimitiveFactory<StreamingPrf> {
    crypto::tink::util::StatusOr<std::unique_ptr<StreamingPrf>> Create(
        const google::crypto::tink::HkdfPrfKey& key) const override {
      return subtle::HkdfStreamingPrf::New(
          crypto::tink::util::Enums::ProtoToSubtle(key.params().hash()),
          key.key_value(), key.params().salt());
    }
  };

  HkdfPrfKeyManager()
      : KeyTypeManager(absl::make_unique<StreamingPrfFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::HkdfPrfKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    status = ValidateKeySize(key.key_value().size());
    if (!status.ok()) return status;
    return ValidateParams(key.params());
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::HkdfPrfKeyFormat& key_format) const override {
    crypto::tink::util::Status status = ValidateKeySize(key_format.key_size());
    if (!status.ok()) return status;
    return ValidateParams(key_format.params());
  }

  crypto::tink::util::StatusOr<google::crypto::tink::HkdfPrfKey> CreateKey(
      const google::crypto::tink::HkdfPrfKeyFormat& key_format) const override {
    google::crypto::tink::HkdfPrfKey key;
    key.set_version(get_version());
    *key.mutable_params() = key_format.params();
    key.set_key_value(
        crypto::tink::subtle::Random::GetRandomBytes(key_format.key_size()));
    return key;
  }

 private:
  crypto::tink::util::Status ValidateKeySize(int key_size) const {
    if (key_size < kMinKeySizeBytes) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          "Invalid HkdfPrfKey: key_value is too short.");
    }
    return crypto::tink::util::Status::OK;
  }

  crypto::tink::util::Status ValidateParams(
      const google::crypto::tink::HkdfPrfParams& params) const {
    // Omitting SHA1 for the moment; there seems to be no reason to allow it.
    if (params.hash() != google::crypto::tink::HashType::SHA256 &&
        params.hash() != google::crypto::tink::HashType::SHA512) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          "Invalid HkdfPrfKey: unsupported hash.");
    }
    return crypto::tink::util::Status::OK;
  }

  // Tink specific minimum key size.
  const int kMinKeySizeBytes = 16;
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::HkdfPrfKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_HKDF_PRF_KEY_MANAGER_H_
