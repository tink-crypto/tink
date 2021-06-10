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
#ifndef THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_CECPQ2_AEAD_HKDF_PRIVATE_KEY_MANAGER_H_
#define THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_CECPQ2_AEAD_HKDF_PRIVATE_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "openssl/hrss.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/hybrid_decrypt.h"
#include "tink/util/enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "pqcrypto/cc/hybrid/cecpq2_aead_hkdf_dem_helper.h"
#include "pqcrypto/cc/hybrid/internal/cecpq2_aead_hkdf_hybrid_decrypt.h"
#include "pqcrypto/proto/cecpq2_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class Cecpq2AeadHkdfPrivateKeyManager
    : public PrivateKeyTypeManager<
          google::crypto::tink::Cecpq2AeadHkdfPrivateKey,
          google::crypto::tink::Cecpq2AeadHkdfKeyFormat,
          google::crypto::tink::Cecpq2AeadHkdfPublicKey, List<HybridDecrypt>> {
 public:
  class HybridDecryptFactory : public PrimitiveFactory<HybridDecrypt> {
    crypto::tink::util::StatusOr<std::unique_ptr<HybridDecrypt>> Create(
        const google::crypto::tink::Cecpq2AeadHkdfPrivateKey&
            cecpq2_private_key) const override {
      return Cecpq2AeadHkdfHybridDecrypt::New(cecpq2_private_key);
    }
  };

  Cecpq2AeadHkdfPrivateKeyManager()
      : PrivateKeyTypeManager(absl::make_unique<HybridDecryptFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::Cecpq2AeadHkdfPrivateKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::Cecpq2AeadHkdfKeyFormat& cecpq2_key_format)
      const override;

  crypto::tink::util::StatusOr<google::crypto::tink::Cecpq2AeadHkdfPrivateKey>
  CreateKey(const google::crypto::tink::Cecpq2AeadHkdfKeyFormat& key_format)
      const override;

  crypto::tink::util::StatusOr<google::crypto::tink::Cecpq2AeadHkdfPublicKey>
  GetPublicKey(const google::crypto::tink::Cecpq2AeadHkdfPrivateKey&
                   private_key) const override;

 private:
  const std::string key_type_ = absl::StrCat(
      "type.googleapis.com/",
      google::crypto::tink::Cecpq2AeadHkdfPrivateKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_EXPERIMENTAL_PQCRYPTO_CC_HYBRID_CECPQ2_AEAD_HKDF_PRIVATE_KEY_MANAGER_H_
