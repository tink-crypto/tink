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

#ifndef TINK_HYBRID_INTERNAL_HPKE_PRIVATE_KEY_MANAGER_H_
#define TINK_HYBRID_INTERNAL_HPKE_PRIVATE_KEY_MANAGER_H_

#include <memory>
#include <string>

#include "tink/core/key_type_manager.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/hybrid/internal/hpke_decrypt.h"
#include "tink/hybrid_decrypt.h"
#include "tink/key_manager.h"
#include "tink/util/constants.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class HpkePrivateKeyManager
    : public PrivateKeyTypeManager<google::crypto::tink::HpkePrivateKey,
                                   google::crypto::tink::HpkeKeyFormat,
                                   google::crypto::tink::HpkePublicKey,
                                   List<HybridDecrypt>> {
 public:
  class HybridDecryptFactory : public PrimitiveFactory<HybridDecrypt> {
    crypto::tink::util::StatusOr<std::unique_ptr<HybridDecrypt>> Create(
        const google::crypto::tink::HpkePrivateKey& private_key)
        const override {
      return HpkeDecrypt::New(private_key);
    }
  };

  HpkePrivateKeyManager()
      : PrivateKeyTypeManager(absl::make_unique<HybridDecryptFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::HpkePrivateKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::HpkeKeyFormat& key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::HpkePrivateKey> CreateKey(
      const google::crypto::tink::HpkeKeyFormat& key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::HpkePublicKey>
  GetPublicKey(
      const google::crypto::tink::HpkePrivateKey& private_key) const override;

 private:
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::HpkePrivateKey().GetTypeName());
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_PRIVATE_KEY_MANAGER_H_
