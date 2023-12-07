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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_KEYDERIVATION_INTERNAL_PRF_BASED_DERIVER_KEY_MANAGER_H_
#define TINK_KEYDERIVATION_INTERNAL_PRF_BASED_DERIVER_KEY_MANAGER_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/keyderivation/internal/prf_based_deriver.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/registry.h"
#include "tink/util/constants.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class PrfBasedDeriverKeyManager
    : public KeyTypeManager<google::crypto::tink::PrfBasedDeriverKey,
                            google::crypto::tink::PrfBasedDeriverKeyFormat,
                            List<KeysetDeriver>> {
 public:
  class KeysetDeriverFactory : public PrimitiveFactory<KeysetDeriver> {
    crypto::tink::util::StatusOr<std::unique_ptr<KeysetDeriver>> Create(
        const google::crypto::tink::PrfBasedDeriverKey& key) const override {
      return internal::PrfBasedDeriver::New(
          key.prf_key(), key.params().derived_key_template());
    }
  };

  PrfBasedDeriverKeyManager()
      : KeyTypeManager(absl::make_unique<
                       PrfBasedDeriverKeyManager::KeysetDeriverFactory>()) {}

  // Returns the version of this key manager.
  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::PrfBasedDeriverKey& key) const override {
    crypto::tink::util::Status status =
        ValidateVersion(key.version(), get_version());
    if (!status.ok()) return status;
    if (!key.has_prf_key()) {
      return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                        "key.prf_key() must be set");
    }
    if (!key.params().has_derived_key_template()) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          "key.params().derived_key_template() must be set");
    }
    return util::OkStatus();
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::PrfBasedDeriverKeyFormat& key_format)
      const override {
    if (!key_format.has_prf_key_template()) {
      return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                        "key.prf_key_template() must be set");
    }
    if (!key_format.params().has_derived_key_template()) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          "key_format.params().derived_key_template() must be set");
    }
    return util::OkStatus();
  }

  crypto::tink::util::StatusOr<google::crypto::tink::PrfBasedDeriverKey>
  CreateKey(const google::crypto::tink::PrfBasedDeriverKeyFormat& key_format)
      const override {
    crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
        prf_key = CreateKeyData(key_format.prf_key_template());
    if (!prf_key.ok()) return prf_key.status();

    // Java and Go implementations perform additional verification by getting a
    // StreamingPrf primitive from the registry and trying to derive
    // `key_format.params().derived_key_template()` with a fake salt. This is
    // currently not possible in C++.

    google::crypto::tink::PrfBasedDeriverKey key;
    key.set_version(get_version());
    *key.mutable_params()->mutable_derived_key_template() =
        key_format.params().derived_key_template();
    *key.mutable_prf_key() = **std::move(prf_key);
    return key;
  }

 protected:
  virtual crypto::tink::util::StatusOr<
      std::unique_ptr<google::crypto::tink::KeyData>>
  CreateKeyData(const google::crypto::tink::KeyTemplate& key_template) const {
    return Registry::NewKeyData(key_template);
  }

 private:
  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom,
                   google::crypto::tink::PrfBasedDeriverKey().GetTypeName());
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_INTERNAL_PRF_BASED_DERIVER_KEY_MANAGER_H_
