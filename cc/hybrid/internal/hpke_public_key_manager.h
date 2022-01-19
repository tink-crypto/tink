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

#ifndef TINK_HYBRID_INTERNAL_HPKE_PUBLIC_KEY_MANAGER_H_
#define TINK_HYBRID_INTERNAL_HPKE_PUBLIC_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/hybrid/internal/hpke_encrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/key_manager.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class HpkePublicKeyManager
    : public KeyTypeManager<google::crypto::tink::HpkePublicKey, void,
                            List<HybridEncrypt>> {
 public:
  class HybridEncryptFactory : public PrimitiveFactory<HybridEncrypt> {
    crypto::tink::util::StatusOr<std::unique_ptr<HybridEncrypt>> Create(
        const google::crypto::tink::HpkePublicKey& public_key) const override {
      return HpkeEncrypt::New(public_key);
    }
  };

  HpkePublicKeyManager()
      : KeyTypeManager(absl::make_unique<HybridEncryptFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::HpkePublicKey& key) const override;

 private:
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::HpkePublicKey().GetTypeName());
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_PUBLIC_KEY_MANAGER_H_
