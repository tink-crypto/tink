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
#ifndef TINK_JWT_INTERNAL_RAW_JWT_HMAC_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_RAW_JWT_HMAC_KEY_MANAGER_H_

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
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

///////////////////////////////////////////////////////////////////////////////
// This key manager creates MAC primitives from JwtHmacKeys. It is by the Tink
// JWT implementation in Python, and should not be used by anybody else.
//
class RawJwtHmacKeyManager
    : public KeyTypeManager<google::crypto::tink::JwtHmacKey,
                            google::crypto::tink::JwtHmacKeyFormat, List<Mac>> {
 public:
  class MacFactory : public PrimitiveFactory<Mac> {
    crypto::tink::util::StatusOr<std::unique_ptr<Mac>> Create(
        const google::crypto::tink::JwtHmacKey& jwt_hmac_key) const override {
      int tag_size;
      google::crypto::tink::HashType hash_type;
      switch (jwt_hmac_key.algorithm()) {
        case google::crypto::tink::JwtHmacAlgorithm::HS256:
          hash_type = google::crypto::tink::HashType::SHA256;
          tag_size = 32;
          break;
        case google::crypto::tink::JwtHmacAlgorithm::HS384:
          hash_type = google::crypto::tink::HashType::SHA384;
          tag_size = 48;
          break;
        case google::crypto::tink::JwtHmacAlgorithm::HS512:
          hash_type = google::crypto::tink::HashType::SHA512;
          tag_size = 64;
          break;
        default:
          return util::Status(util::error::INVALID_ARGUMENT,
                              "Unknown algorithm.");
      }
      return subtle::HmacBoringSsl::New(
          util::Enums::ProtoToSubtle(hash_type), tag_size,
          util::SecretDataFromStringView(jwt_hmac_key.key_value()));
    }
  };

  RawJwtHmacKeyManager() : KeyTypeManager(absl::make_unique<MacFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

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
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::JwtHmacKey().GetTypeName());
};

}  // namespace jwt_internal

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_RAW_JWT_HMAC_KEY_MANAGER_H_
