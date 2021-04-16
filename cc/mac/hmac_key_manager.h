// Copyright 2017 Google Inc.
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
#ifndef TINK_MAC_HMAC_KEY_MANAGER_H_
#define TINK_MAC_HMAC_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/mac.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class HmacKeyManager
    : public KeyTypeManager<google::crypto::tink::HmacKey,
                            google::crypto::tink::HmacKeyFormat, List<Mac>> {
 public:
  class MacFactory : public PrimitiveFactory<Mac> {
    crypto::tink::util::StatusOr<std::unique_ptr<Mac>> Create(
        const google::crypto::tink::HmacKey& hmac_key) const override {
      return subtle::HmacBoringSsl::New(
          util::Enums::ProtoToSubtle(hmac_key.params().hash()),
          hmac_key.params().tag_size(),
          util::SecretDataFromStringView(hmac_key.key_value()));
    }
  };

  HmacKeyManager() : KeyTypeManager(absl::make_unique<MacFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::HmacKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::HmacKeyFormat& key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::HmacKey> CreateKey(
      const google::crypto::tink::HmacKeyFormat& key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::HmacKey> DeriveKey(
      const google::crypto::tink::HmacKeyFormat& key_format,
      InputStream* input_stream) const override;

  internal::FipsCompatibility FipsStatus() const override {
    return internal::FipsCompatibility::kRequiresBoringCrypto;
  }

 private:
  crypto::tink::util::Status ValidateParams(
      const google::crypto::tink::HmacParams& params) const;

  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::HmacKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_HMAC_KEY_MANAGER_H_
