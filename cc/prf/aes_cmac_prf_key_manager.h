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
#ifndef TINK_PRF_AES_CMAC_PRF_KEY_MANAGER_H_
#define TINK_PRF_AES_CMAC_PRF_KEY_MANAGER_H_

#include <algorithm>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/core/key_type_manager.h"
#include "tink/key_manager.h"
#include "tink/subtle/prf/prf_set_util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stateful_cmac_boringssl.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class AesCmacPrfKeyManager
    : public KeyTypeManager<google::crypto::tink::AesCmacPrfKey,
                            google::crypto::tink::AesCmacPrfKeyFormat,
                            List<Prf>> {
 public:
  class PrfSetFactory : public PrimitiveFactory<Prf> {
    crypto::tink::util::StatusOr<std::unique_ptr<Prf>> Create(
        const google::crypto::tink::AesCmacPrfKey& key) const override {
      return subtle::CreatePrfFromStatefulMacFactory(
          absl::make_unique<subtle::StatefulCmacBoringSslFactory>(
              AesCmacPrfKeyManager::MaxOutputLength(),
              util::SecretDataFromStringView(key.key_value())));
    }
  };

  AesCmacPrfKeyManager()
      : KeyTypeManager(
            absl::make_unique<AesCmacPrfKeyManager::PrfSetFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  static uint64_t MaxOutputLength() { return 16; }
  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::AesCmacPrfKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    if (key.key_value().size() != kKeySizeInBytes) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          "Invalid AesCmacPrfKey: key_value wrong length.");
    }
    return util::OkStatus();
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::AesCmacPrfKeyFormat& key_format)
      const override {
    crypto::tink::util::Status status =
        ValidateVersion(key_format.version(), get_version());
    if (!status.ok()) return status;
    if (key_format.key_size() != kKeySizeInBytes) {
      return crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT,
          "Invalid AesCmacPrfKeyFormat: invalid key_size.");
    }
    return util::OkStatus();
  }

  crypto::tink::util::StatusOr<google::crypto::tink::AesCmacPrfKey> CreateKey(
      const google::crypto::tink::AesCmacPrfKeyFormat& key_format)
      const override {
    google::crypto::tink::AesCmacPrfKey key;
    key.set_version(get_version());
    key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
    return key;
  }

  crypto::tink::util::StatusOr<google::crypto::tink::AesCmacPrfKey> DeriveKey(
      const google::crypto::tink::AesCmacPrfKeyFormat& key_format,
      InputStream* input_stream) const override {
    auto status = ValidateKeyFormat(key_format);
    if (!status.ok()) {
      return status;
    }
    crypto::tink::util::StatusOr<std::string> randomness =
        ReadBytesFromStream(key_format.key_size(), input_stream);
    if (!randomness.status().ok()) {
      return randomness.status();
    }
    google::crypto::tink::AesCmacPrfKey key;
    key.set_version(get_version());
    key.set_key_value(randomness.ValueOrDie());
    return key;
  }

  FipsCompatibility FipsStatus() const override {
    return FipsCompatibility::kNotFips;
  }

 private:
  // Due to https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf,
  // we only allow key sizes of 256 bit.
  const int kKeySizeInBytes = 32;

  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::AesCmacPrfKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_AES_CMAC_PRF_KEY_MANAGER_H_
