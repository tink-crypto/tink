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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_FALCON_SIGN_KEY_MANAGER_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_FALCON_SIGN_KEY_MANAGER_H_

#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/public_key_sign.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/experimental/pqcrypto/falcon.pb.h"

namespace crypto {
namespace tink {

class FalconSignKeyManager
    : public PrivateKeyTypeManager<google::crypto::tink::FalconPrivateKey,
                                   google::crypto::tink::FalconKeyFormat,
                                   google::crypto::tink::FalconPublicKey,
                                   List<PublicKeySign>> {
 public:
  class PublicKeySignFactory : public PrimitiveFactory<PublicKeySign> {
    crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>> Create(
        const google::crypto::tink::FalconPrivateKey& private_key)
        const override;
  };

  FalconSignKeyManager()
      : PrivateKeyTypeManager(absl::make_unique<PublicKeySignFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::FalconPrivateKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::FalconKeyFormat& key_format)
      const override;

  crypto::tink::util::StatusOr<google::crypto::tink::FalconPrivateKey>
  CreateKey(const google::crypto::tink::FalconKeyFormat& key_format)
      const override;

  crypto::tink::util::StatusOr<google::crypto::tink::FalconPublicKey>
  GetPublicKey(const google::crypto::tink::FalconPrivateKey& private_key)
      const override {
    return private_key.public_key();
  }

 private:
  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom,
                   google::crypto::tink::FalconPrivateKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_FALCON_SIGN_KEY_MANAGER_H_
