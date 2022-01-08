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
#ifndef TINK_JWT_INTERNAL_JWT_HMAC_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_JWT_HMAC_KEY_MANAGER_H_

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/jwt/internal/jwt_mac_impl.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/internal/raw_jwt_hmac_key_manager.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/jwt_hmac.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class JwtHmacKeyManager
    : public KeyTypeManager<google::crypto::tink::JwtHmacKey,
                            google::crypto::tink::JwtHmacKeyFormat,
                            List<JwtMacInternal>> {
 public:
  class JwtMacFactory : public PrimitiveFactory<JwtMacInternal> {
    crypto::tink::util::StatusOr<std::unique_ptr<JwtMacInternal>> Create(
        const google::crypto::tink::JwtHmacKey& jwt_hmac_key) const override {
      int tag_size;
      std::string algorithm;
      google::crypto::tink::HashType hash_type;
      switch (jwt_hmac_key.algorithm()) {
        case google::crypto::tink::JwtHmacAlgorithm::HS256:
          hash_type = google::crypto::tink::HashType::SHA256;
          tag_size = 32;
          algorithm = "HS256";
          break;
        case google::crypto::tink::JwtHmacAlgorithm::HS384:
          hash_type = google::crypto::tink::HashType::SHA384;
          tag_size = 48;
          algorithm = "HS384";
          break;
        case google::crypto::tink::JwtHmacAlgorithm::HS512:
          hash_type = google::crypto::tink::HashType::SHA512;
          tag_size = 64;
          algorithm = "HS512";
          break;
        default:
          return util::Status(absl::StatusCode::kInvalidArgument,
                              "Unknown algorithm.");
      }
      crypto::tink::util::StatusOr<std::unique_ptr<Mac>> mac =
          subtle::HmacBoringSsl::New(
              util::Enums::ProtoToSubtle(hash_type), tag_size,
              util::SecretDataFromStringView(jwt_hmac_key.key_value()));
      if (!mac.ok()) {
        return mac.status();
      }
      absl::optional<std::string> custom_kid = absl::nullopt;
      if (jwt_hmac_key.has_custom_kid()) {
        custom_kid = jwt_hmac_key.custom_kid().value();
      }
      std::unique_ptr<JwtMacInternal> jwt_mac =
          absl::make_unique<jwt_internal::JwtMacImpl>(*std::move(mac),
                                                      algorithm, custom_kid);
      return jwt_mac;
    }
  };

  JwtHmacKeyManager() : KeyTypeManager(absl::make_unique<JwtMacFactory>()) {}

  uint32_t get_version() const override;

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override;

  const std::string& get_key_type() const override;

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::JwtHmacKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::JwtHmacKeyFormat& key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::JwtHmacKey> CreateKey(
      const google::crypto::tink::JwtHmacKeyFormat& key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::JwtHmacKey> DeriveKey(
      const google::crypto::tink::JwtHmacKeyFormat& key_format,
      InputStream* input_stream) const override;

 private:
  const RawJwtHmacKeyManager raw_key_manager_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_HMAC_KEY_MANAGER_H_
