// Copyright 2019 Google Inc.
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
#ifndef TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_KEY_MANAGER_H_
#define TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_KEY_MANAGER_H_

#include <algorithm>
#include <vector>

#include "absl/strings/string_view.h"
#include "tink/core/key_type_manager.h"
#include "tink/key_manager.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/aes_gcm_hkdf_streaming.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class AesGcmHkdfStreamingKeyManager
    : public KeyTypeManager<google::crypto::tink::AesGcmHkdfStreamingKey,
                            google::crypto::tink::AesGcmHkdfStreamingKeyFormat,
                            List<StreamingAead>> {
 public:
  class AesGcmHkdfStreamingKeyManagerFactory
      : public PrimitiveFactory<StreamingAead> {
    crypto::tink::util::StatusOr<std::unique_ptr<StreamingAead>> Create(
        const google::crypto::tink::AesGcmHkdfStreamingKey& key)
        const override {
      auto streaming_result = crypto::tink::subtle::AesGcmHkdfStreaming::New(
          key.key_value(),
          crypto::tink::util::Enums::ProtoToSubtle(
              key.params().hkdf_hash_type()),
          key.params().derived_key_size(),
          key.params().ciphertext_segment_size(),
          /* ciphertext_offset = */ 0);
      if (!streaming_result.ok()) return streaming_result.status();
      return {std::move(streaming_result.ValueOrDie())};
    }
  };

  AesGcmHkdfStreamingKeyManager()
      : KeyTypeManager(
            absl::make_unique<AesGcmHkdfStreamingKeyManager::
                                  AesGcmHkdfStreamingKeyManagerFactory>()) {}

  // Returns the version of this key manager.
  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::AesGcmHkdfStreamingKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::AesGcmHkdfStreamingKeyFormat& key_format)
      const override;

  crypto::tink::util::StatusOr<google::crypto::tink::AesGcmHkdfStreamingKey>
  CreateKey(const google::crypto::tink::AesGcmHkdfStreamingKeyFormat&
                key_format) const override;

  ~AesGcmHkdfStreamingKeyManager() override {}

 private:
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom,
      google::crypto::tink::AesGcmHkdfStreamingKey().GetTypeName());

  static crypto::tink::util::Status Validate(
      const google::crypto::tink::AesGcmHkdfStreamingKeyFormat& key_format);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_KEY_MANAGER_H_
