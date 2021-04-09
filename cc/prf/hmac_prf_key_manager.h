// Copyright 2020 Google LLC
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
#ifndef TINK_PRF_HMAC_PRF_KEY_MANAGER_H_
#define TINK_PRF_HMAC_PRF_KEY_MANAGER_H_

#include <algorithm>
#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/core/key_type_manager.h"
#include "tink/key_manager.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/prf/prf_set_util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stateful_hmac_boringssl.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/hmac_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class HmacPrfKeyManager
    : public KeyTypeManager<google::crypto::tink::HmacPrfKey,
                            google::crypto::tink::HmacPrfKeyFormat, List<Prf>> {
 public:
  class PrfFactory : public PrimitiveFactory<Prf> {
    crypto::tink::util::StatusOr<std::unique_ptr<Prf>> Create(
        const google::crypto::tink::HmacPrfKey& key) const override {
      return subtle::CreatePrfFromStatefulMacFactory(
          absl::make_unique<subtle::StatefulHmacBoringSslFactory>(
              util::Enums::ProtoToSubtle(key.params().hash()),
              MaxOutputLength(util::Enums::ProtoToSubtle(key.params().hash())),
              util::SecretDataFromStringView(key.key_value())));
    }
  };

  HmacPrfKeyManager()
      : KeyTypeManager(absl::make_unique<HmacPrfKeyManager::PrfFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  static uint64_t MaxOutputLength(subtle::HashType hash_type) {
    static std::map<subtle::HashType, uint64_t>* max_output_length =
        new std::map<subtle::HashType, uint64_t>(
            {{subtle::HashType::SHA1, 20},
             {subtle::HashType::SHA256, 32},
             {subtle::HashType::SHA512, 64}});
    auto length_it = max_output_length->find(hash_type);
    if (length_it == max_output_length->end()) {
      return 0;
    }
    return length_it->second;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::HmacPrfKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::HmacPrfKeyFormat& key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::HmacPrfKey> CreateKey(
      const google::crypto::tink::HmacPrfKeyFormat& key_format) const override;

  util::StatusOr<google::crypto::tink::HmacPrfKey> DeriveKey(
      const google::crypto::tink::HmacPrfKeyFormat& hmac_prf_key_format,
      InputStream* input_stream) const override;

  FipsCompatibility FipsStatus() const override {
    return FipsCompatibility::kRequiresBoringCrypto;
  }

 private:
  util::Status ValidateParams(
      const google::crypto::tink::HmacPrfParams& params) const;

  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom, google::crypto::tink::HmacPrfKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_HMAC_PRF_KEY_MANAGER_H_
