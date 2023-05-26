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

#include "tink/hybrid/ecies_aead_hkdf_dem_helper.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/deterministic_aead.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/aes_siv_boringssl.h"
#include "tink/subtle/xchacha20_poly1305_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/statusor.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_siv.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::AeadOrDaead;
using ::google::crypto::tink::AesCtrHmacAeadKey;
using ::google::crypto::tink::AesCtrHmacAeadKeyFormat;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::AesSivKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;

crypto::tink::util::StatusOr<std::unique_ptr<AeadOrDaead>> Wrap(
    crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::Aead>> aead_or) {
  if (!aead_or.ok()) {
    return aead_or.status();
  }
  return std::make_unique<AeadOrDaead>(std::move(aead_or.value()));
}

crypto::tink::util::StatusOr<std::unique_ptr<AeadOrDaead>> Wrap(
    crypto::tink::util::StatusOr<
        std::unique_ptr<crypto::tink::DeterministicAead>>
        daead_or) {
  if (!daead_or.ok()) {
    return daead_or.status();
  }
  return std::make_unique<AeadOrDaead>(std::move(daead_or.value()));
}

}  // namespace

util::StatusOr<EciesAeadHkdfDemHelper::DemKeyParams>
EciesAeadHkdfDemHelper::GetKeyParams(const KeyTemplate& key_template) {
  const std::string& type_url = key_template.type_url();
  if (type_url == "type.googleapis.com/google.crypto.tink.AesGcmKey") {
    AesGcmKeyFormat key_format;
    if (!key_format.ParseFromString(key_template.value())) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid AesGcmKeyFormat in DEM key template");
    }
    return {{AES_GCM_KEY, key_format.key_size()}};
  }
  if (type_url == "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey") {
    AesCtrHmacAeadKeyFormat key_format;
    if (!key_format.ParseFromString(key_template.value())) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid AesCtrHmacKeyFormat in DEM key template");
    }
    uint32_t dem_key_size = key_format.aes_ctr_key_format().key_size() +
                            key_format.hmac_key_format().key_size();
    return {{AES_CTR_HMAC_AEAD_KEY, dem_key_size,
             key_format.aes_ctr_key_format().key_size(),
             key_format.aes_ctr_key_format().params().iv_size(),
             key_format.hmac_key_format().params().hash(),
             key_format.hmac_key_format().params().tag_size()}};
  }
  if (type_url ==
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key") {
    if (!XChaCha20Poly1305KeyFormat().ParseFromString(key_template.value())) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid XChaCha20KeyFormat in DEM key template");
    }
    return {{XCHACHA20_POLY1305_KEY, 32}};
  }
  if (type_url == "type.googleapis.com/google.crypto.tink.AesSivKey") {
    AesSivKeyFormat key_format;

    if (!key_format.ParseFromString(key_template.value())) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid AesSiveKeyFormat in DEM key template");
    }
    return {{AES_SIV_KEY, key_format.key_size()}};
  }
  return ToStatusF(absl::StatusCode::kInvalidArgument,
                   "Unsupported DEM key type '%s'.", type_url);
}

// static
util::StatusOr<std::unique_ptr<const EciesAeadHkdfDemHelper>>
EciesAeadHkdfDemHelper::New(const KeyTemplate& dem_key_template) {
  auto key_params_or = GetKeyParams(dem_key_template);
  if (!key_params_or.ok()) return key_params_or.status();
  DemKeyParams key_params = key_params_or.value();
  return absl::WrapUnique<const EciesAeadHkdfDemHelper>(
      new EciesAeadHkdfDemHelper(dem_key_template, key_params));
}

crypto::tink::util::StatusOr<std::unique_ptr<AeadOrDaead>>
EciesAeadHkdfDemHelper::GetAeadOrDaead(
    const util::SecretData& symmetric_key_value) const {
  if (symmetric_key_value.size() != key_params_.key_size_in_bytes) {
    return util::Status(absl::StatusCode::kInternal,
                        "Wrong length of symmetric key.");
  }
  switch (key_params_.key_type) {
    case AES_GCM_KEY:
      return Wrap(subtle::AesGcmBoringSsl::New(symmetric_key_value));
    case AES_CTR_HMAC_AEAD_KEY: {
      AesCtrHmacAeadKey key;
      auto aes_ctr_key = key.mutable_aes_ctr_key();
      aes_ctr_key->mutable_params()->set_iv_size(
          key_params_.aes_ctr_key_iv_size_in_bytes);
      aes_ctr_key->set_key_value(
          std::string(util::SecretDataAsStringView(symmetric_key_value)
                          .substr(0, key_params_.aes_ctr_key_size_in_bytes)));
      auto hmac_key = key.mutable_hmac_key();
      hmac_key->mutable_params()->set_tag_size(
          key_params_.hmac_key_tag_size_in_bytes);
      hmac_key->mutable_params()->set_hash(key_params_.hmac_key_hash);
      hmac_key->set_key_value(
          std::string(util::SecretDataAsStringView(symmetric_key_value)
                          .substr(key_params_.aes_ctr_key_size_in_bytes)));
      return Wrap(AesCtrHmacAeadKeyManager().GetPrimitive<Aead>(key));
    }
    case XCHACHA20_POLY1305_KEY:
      return Wrap(subtle::XChacha20Poly1305BoringSsl::New(symmetric_key_value));
    case AES_SIV_KEY:
      return Wrap(subtle::AesSivBoringSsl::New(symmetric_key_value));
  }
}

}  // namespace tink
}  // namespace crypto
