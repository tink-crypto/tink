// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
#include "tink/prf/prf_key_templates.h"

#include "absl/memory/memory.h"
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/hmac_prf.pb.h"

namespace crypto {
namespace tink {

namespace {

using google::crypto::tink::AesCmacPrfKeyFormat;
using google::crypto::tink::HkdfPrfKeyFormat;
using google::crypto::tink::HmacPrfKeyFormat;

std::unique_ptr<google::crypto::tink::KeyTemplate> NewHkdfSha256Template() {
  auto key_template = absl::make_unique<google::crypto::tink::KeyTemplate>();
  auto hkdf_prf_key_manager = absl::make_unique<HkdfPrfKeyManager>();
  key_template->set_type_url(hkdf_prf_key_manager->get_key_type());
  key_template->set_output_prefix_type(
      google::crypto::tink::OutputPrefixType::RAW);
  HkdfPrfKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.set_version(hkdf_prf_key_manager->get_version());
  key_format.mutable_params()->set_hash(google::crypto::tink::HashType::SHA256);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

std::unique_ptr<google::crypto::tink::KeyTemplate> NewHmacTemplate(
    google::crypto::tink::HashType hash_type, uint32_t key_size) {
  auto key_template = absl::make_unique<google::crypto::tink::KeyTemplate>();
  auto hmac_prf_key_manager = absl::make_unique<HmacPrfKeyManager>();
  key_template->set_type_url(hmac_prf_key_manager->get_key_type());
  key_template->set_output_prefix_type(
      google::crypto::tink::OutputPrefixType::RAW);
  HmacPrfKeyFormat key_format;
  key_format.set_key_size(key_size);
  key_format.set_version(hmac_prf_key_manager->get_version());
  key_format.mutable_params()->set_hash(hash_type);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

std::unique_ptr<google::crypto::tink::KeyTemplate> NewAesCmacTemplate() {
  auto key_template = absl::make_unique<google::crypto::tink::KeyTemplate>();
  auto aes_cmac_prf_key_manager = absl::make_unique<AesCmacPrfKeyManager>();
  key_template->set_type_url(aes_cmac_prf_key_manager->get_key_type());
  key_template->set_output_prefix_type(
      google::crypto::tink::OutputPrefixType::RAW);
  AesCmacPrfKeyFormat key_format;
  key_format.set_version(aes_cmac_prf_key_manager->get_version());
  key_format.set_key_size(32);
  key_format.SerializeToString(key_template->mutable_value());
  return key_template;
}

}  // namespace

const google::crypto::tink::KeyTemplate& PrfKeyTemplates::HkdfSha256() {
  static const google::crypto::tink::KeyTemplate* key_template =
      NewHkdfSha256Template().release();
  return *key_template;
}

const google::crypto::tink::KeyTemplate& PrfKeyTemplates::HmacSha256() {
  static const google::crypto::tink::KeyTemplate* key_template =
      NewHmacTemplate(google::crypto::tink::HashType::SHA256, 32).release();
  return *key_template;
}

const google::crypto::tink::KeyTemplate& PrfKeyTemplates::HmacSha512() {
  static const google::crypto::tink::KeyTemplate* key_template =
      NewHmacTemplate(google::crypto::tink::HashType::SHA512, 64).release();
  return *key_template;
}

const google::crypto::tink::KeyTemplate& PrfKeyTemplates::AesCmac() {
  static const google::crypto::tink::KeyTemplate* key_template =
      NewAesCmacTemplate().release();
  return *key_template;
}

}  // namespace tink
}  // namespace crypto
