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

#include "cc/hybrid/ecies_aead_hkdf_dem_helper.h"

#include "cc/aead.h"
#include "cc/key_manager.h"
#include "cc/registry.h"
#include "cc/util/ptr_util.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesGcmKey;
using google::crypto::tink::AesGcmKeyFormat;
using google::crypto::tink::KeyTemplate;
using util::Status;
using util::StatusOr;

namespace crypto {
namespace tink {

// static
StatusOr<std::unique_ptr<EciesAeadHkdfDemHelper>>
EciesAeadHkdfDemHelper::New(const KeyTemplate& dem_key_template) {
  auto helper = util::wrap_unique(new EciesAeadHkdfDemHelper(dem_key_template));
  std::string dem_type_url = dem_key_template.type_url();
  if (dem_type_url == "type.googleapis.com/google.crypto.tink.AesGcmKey") {
    helper->dem_key_type_ = AES_GCM_KEY;
    AesGcmKeyFormat gcm_key_format;
    if (!gcm_key_format.ParseFromString(dem_key_template.value())) {
      return Status(util::error::INVALID_ARGUMENT,
                    "Invalid AesGcmKeyFormat in DEM key template");
    }
    helper->dem_key_size_in_bytes_ = gcm_key_format.key_size();
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Unsupported DEM key type '%s'.", dem_type_url.c_str());
  }
  auto key_manager_result =
      Registry::get_default_registry().get_key_manager<Aead>(dem_type_url);
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
    return Status(util::error::INTERNAL,
                  "Wrong length of symmetric key.");
  }
  auto new_key_result = dem_key_manager_->NewKey(dem_key_template_);
  if (!new_key_result.ok()) return new_key_result.status();
  auto new_key = std::move(new_key_result.ValueOrDie());
  if (!ReplaceKeyBytes(symmetric_key_value, new_key.get())) {
    return Status(util::error::INTERNAL, "Generation of DEM-key failed.");
  }
  return dem_key_manager_->GetPrimitive(*new_key);
}


bool EciesAeadHkdfDemHelper::ReplaceKeyBytes(
    const std::string& key_bytes, google::protobuf::Message* key) const {
  if (dem_key_type_ == AES_GCM_KEY) {
    AesGcmKey* aes_gcm_key = reinterpret_cast<AesGcmKey*>(key);
    aes_gcm_key->set_key_value(key_bytes);
    return true;
  }
  return false;
}

}  // namespace tink
}  // namespace crypto
