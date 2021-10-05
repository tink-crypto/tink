// Copyright 2021 Google LLC
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
#ifndef TINK_INTEGRATION_TPM_MAC_TPM_HMAC_KEY_MANAGER_H_
#define TINK_INTEGRATION_TPM_MAC_TPM_HMAC_KEY_MANAGER_H_

#include "tink/core/key_type_manager.h"
#include "tink/mac.h"
#include "tink/util/constants.h"
#include "tink/util/statusor.h"
#include "proto/tpm_hmac.pb.h"

namespace crypto {
namespace tink {
namespace integration {
namespace tpm {

class TpmHmacKeyManager
    : public KeyTypeManager<google::crypto::tink::TpmHmacKey,
                            google::crypto::tink::TpmHmacKeyFormat, List<Mac>> {
 public:
  class MacFactory : public PrimitiveFactory<Mac> {
    crypto::tink::util::StatusOr<std::unique_ptr<Mac>> Create(
        const google::crypto::tink::TpmHmacKey& tpm_hmac_key) const override;
  };

  TpmHmacKeyManager() : KeyTypeManager(absl::make_unique<MacFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::REMOTE;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::TpmHmacKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::TpmHmacKeyFormat& key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::TpmHmacKey> CreateKey(
      const google::crypto::tink::TpmHmacKeyFormat& key_format) const override;

 private:
  crypto::tink::util::Status ValidateParams(
      const google::crypto::tink::TpmHmacParams& params) const;

  crypto::tink::util::Status ValidateAuthPolicy(
      const google::crypto::tink::TpmObjectAuthPolicy& auth_policy) const;

  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::TpmHmacKey().GetTypeName());
};

}  // namespace tpm
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_TPM_HMAC_TPM_MAC_KEY_MANAGER_H_
