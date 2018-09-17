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

#include "absl/memory/memory.h"
#include "tink/aead.h"
#include "tink/key_manager.h"
#include "tink/registry.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/statusor.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::AesCtrHmacAeadKey;
using google::crypto::tink::AesCtrHmacAeadKeyFormat;
using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyTemplate;


namespace crypto {
namespace tink {

// static
StatusOr<std::unique_ptr<EciesAeadHkdfDemHelper>> EciesAeadHkdfDemHelper::New(
    const KeyTemplate& dem_key_template) {
  auto helper = absl::WrapUnique(new EciesAeadHkdfDemHelper(dem_key_template));
  std::string dem_type_url = dem_key_template.type_url();
  if (dem_type_url == "type.googleapis.com/google.crypto.tink.AesGcmKey") {
    helper->dem_key_type_ = AES_GCM_KEY;
    AesGcmKeyFormat key_format;
    if (!key_format.ParseFromString(dem_key_template.value())) {
      return Status(util::error::INVALID_ARGUMENT,
                    "Invalid AesGcmKeyFormat in DEM key template");
    }
    helper->dem_key_size_in_bytes_ = key_format.key_size();
  } else if (dem_type_url ==
             "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey") {
    helper->dem_key_type_ = AES_CTR_HMAC_AEAD_KEY;
    AesCtrHmacAeadKeyFormat key_format;
    if (!key_format.ParseFromString(dem_key_template.value())) {
      return Status(util::error::INVALID_ARGUMENT,
                    "Invalid AesCtrHmacAeadKeyFormat in DEM key template");
    }
    helper->aes_ctr_key_size_in_bytes_ =
        key_format.aes_ctr_key_format().key_size();
    helper->dem_key_size_in_bytes_ = helper->aes_ctr_key_size_in_bytes_ +
                                     key_format.hmac_key_format().key_size();
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Unsupported DEM key type '%s'.", dem_type_url.c_str());
  }
  auto key_manager_result = Registry::get_key_manager<Aead>(dem_type_url);
  if (!key_manager_result.ok()) {
    return ToStatusF(util::error::FAILED_PRECONDITION,
                     "No manager for DEM key type '%s' found in the registry.",
                     dem_type_url.c_str());
  }
  helper->dem_key_manager_ = key_manager_result.ValueOrDie();
  return std::move(helper);
}

StatusOr<std::unique_ptr<Aead>> EciesAeadHkdfDemHelper::GetAead(
    const std::string& symmetric_key_value) const {
  if (symmetric_key_value.size() != dem_key_size_in_bytes_) {
    return Status(util::error::INTERNAL, "Wrong length of symmetric key.");
  }
  auto new_key_result =
      dem_key_manager_->get_key_factory().NewKey(dem_key_template_.value());
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = std::move(new_key_result.ValueOrDie());
  if (!ReplaceKeyBytes(symmetric_key_value, new_key.get())) {
    return Status(util::error::INTERNAL, "Generation of DEM-key failed.");
  }
  return dem_key_manager_->GetPrimitive(*new_key);
}

bool EciesAeadHkdfDemHelper::ReplaceKeyBytes(
    const std::string& key_bytes, portable_proto::MessageLite* proto) const {
  if (dem_key_type_ == AES_GCM_KEY) {
    AesGcmKey* key = static_cast<AesGcmKey*>(proto);
    key->set_key_value(key_bytes);
    return true;
  } else if (dem_key_type_ == AES_CTR_HMAC_AEAD_KEY) {
    AesCtrHmacAeadKey* key = static_cast<AesCtrHmacAeadKey*>(proto);
    auto aes_ctr_key = key->mutable_aes_ctr_key();
    aes_ctr_key->set_key_value(key_bytes.substr(0, aes_ctr_key_size_in_bytes_));
    auto hmac_key = key->mutable_hmac_key();
    hmac_key->set_key_value(
        key_bytes.substr(aes_ctr_key_size_in_bytes_,
                         key_bytes.size() - aes_ctr_key_size_in_bytes_));
    return true;
  }
  return false;
}

}  // namespace tink
}  // namespace crypto
