// Copyright 2019 Google LLC
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
#ifndef TINK_STREAMINGAEAD_AES_CTR_HMAC_STREAMING_KEY_MANAGER_H_
#define TINK_STREAMINGAEAD_AES_CTR_HMAC_STREAMING_KEY_MANAGER_H_

#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/aes_ctr_hmac_streaming.h"
#include "tink/util/constants.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_ctr_hmac_streaming.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class AesCtrHmacStreamingKeyManager
    : public KeyTypeManager<google::crypto::tink::AesCtrHmacStreamingKey,
                            google::crypto::tink::AesCtrHmacStreamingKeyFormat,
                            List<StreamingAead>> {
 public:
  class StreamingAeadFactory
      : public PrimitiveFactory<StreamingAead> {
    crypto::tink::util::StatusOr<std::unique_ptr<StreamingAead>> Create(
        const google::crypto::tink::AesCtrHmacStreamingKey& key)
        const override {
          subtle::AesCtrHmacStreaming::Params params;
          params.ikm = util::SecretDataFromStringView(key.key_value());
          params.hkdf_algo = crypto::tink::util::Enums::ProtoToSubtle(
              key.params().hkdf_hash_type());
          params.key_size = key.params().derived_key_size();
          params.ciphertext_segment_size =
              key.params().ciphertext_segment_size();
          params.ciphertext_offset = 0;
          params.tag_algo = crypto::tink::util::Enums::ProtoToSubtle(
              key.params().hmac_params().hash());
          params.tag_size = key.params().hmac_params().tag_size();
          auto streaming_result =
              crypto::tink::subtle::AesCtrHmacStreaming::New(params);
          if (!streaming_result.ok()) return streaming_result.status();
          return {std::move(streaming_result.ValueOrDie())};
        }
  };

  AesCtrHmacStreamingKeyManager()
      : KeyTypeManager(
            absl::make_unique<AesCtrHmacStreamingKeyManager::
                                  StreamingAeadFactory>()) {}

  // Returns the version of this key manager.
  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  crypto::tink::util::Status ValidateKey(
      const google::crypto::tink::AesCtrHmacStreamingKey& key) const override;

  crypto::tink::util::Status ValidateKeyFormat(
      const google::crypto::tink::AesCtrHmacStreamingKeyFormat& key_format)
      const override;

  crypto::tink::util::StatusOr<google::crypto::tink::AesCtrHmacStreamingKey>
  CreateKey(const google::crypto::tink::AesCtrHmacStreamingKeyFormat&
                key_format) const override;

  crypto::tink::util::StatusOr<google::crypto::tink::AesCtrHmacStreamingKey>
  DeriveKey(
      const google::crypto::tink::AesCtrHmacStreamingKeyFormat& key_format,
      InputStream* input_stream) const override;

  ~AesCtrHmacStreamingKeyManager() override {}

 private:
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom,
      google::crypto::tink::AesCtrHmacStreamingKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_AES_CTR_HMAC_STREAMING_KEY_MANAGER_H_
