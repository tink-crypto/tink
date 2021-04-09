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

#include "tink/jwt/internal/jwt_hmac_key_manager.h"

#include <map>

#include "absl/strings/string_view.h"
#include "tink/jwt/internal/raw_jwt_hmac_key_manager.h"
#include "tink/mac.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtHmacKey;
using google::crypto::tink::JwtHmacKeyFormat;

uint32_t JwtHmacKeyManager::get_version() const {
  return raw_key_manager_.get_version();
}

google::crypto::tink::KeyData::KeyMaterialType
JwtHmacKeyManager::key_material_type() const {
  return raw_key_manager_.key_material_type();
}

const std::string& JwtHmacKeyManager::get_key_type() const {
  return raw_key_manager_.get_key_type();
}

StatusOr<JwtHmacKey> JwtHmacKeyManager::CreateKey(
    const JwtHmacKeyFormat& jwt_hmac_key_format) const {
  return raw_key_manager_.CreateKey(jwt_hmac_key_format);
}

StatusOr<JwtHmacKey> JwtHmacKeyManager::DeriveKey(
    const JwtHmacKeyFormat& jwt_hmac_key_format,
    InputStream* input_stream) const {
  return raw_key_manager_.DeriveKey(jwt_hmac_key_format, input_stream);
}

Status JwtHmacKeyManager::ValidateKey(const JwtHmacKey& key) const {
  return raw_key_manager_.ValidateKey(key);
}

Status JwtHmacKeyManager::ValidateKeyFormat(
    const JwtHmacKeyFormat& key_format) const {
  return raw_key_manager_.ValidateKeyFormat(key_format);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
