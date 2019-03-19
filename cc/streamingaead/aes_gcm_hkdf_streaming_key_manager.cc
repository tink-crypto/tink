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

#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"

#include "absl/strings/string_view.h"
#include "tink/key_manager.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/aes_gcm_hkdf_streaming.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesGcmHkdfStreamingKey;
using ::google::crypto::tink::AesGcmHkdfStreamingKeyFormat;
using ::google::crypto::tink::AesGcmHkdfStreamingParams;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;

namespace {

Status ValidateParams(const AesGcmHkdfStreamingParams& params) {
  if (!(params.hkdf_hash_type() == HashType::SHA1 ||
        params.hkdf_hash_type() == HashType::SHA256 ||
        params.hkdf_hash_type() == HashType::SHA512)) {
    return Status(util::error::INVALID_ARGUMENT,
                  "unsupported hkdf_hash_type");
  }
  if (params.ciphertext_segment_size() <
      (params.derived_key_size() + 8) + 16) {  // header_size + tag_size
    return Status(util::error::INVALID_ARGUMENT,
                  "ciphertext_segment_size too small");
  }
  return ValidateAesKeySize(params.derived_key_size());
}

}  // namespace

class AesGcmHkdfStreamingKeyFactory : public KeyFactoryBase<
    AesGcmHkdfStreamingKey, AesGcmHkdfStreamingKeyFormat> {
 public:
  AesGcmHkdfStreamingKeyFactory() {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

 protected:
  StatusOr<std::unique_ptr<AesGcmHkdfStreamingKey>> NewKeyFromFormat(
      const AesGcmHkdfStreamingKeyFormat& key_format) const override {
    Status status = AesGcmHkdfStreamingKeyManager::Validate(key_format);
    if (!status.ok()) return status;
    auto key = absl::make_unique<AesGcmHkdfStreamingKey>();
    key->set_version(AesGcmHkdfStreamingKeyManager::kVersion);
    key->set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
    *key->mutable_params() = key_format.params();
    return {std::move(key)};
  }
};

constexpr uint32_t AesGcmHkdfStreamingKeyManager::kVersion;

AesGcmHkdfStreamingKeyManager::AesGcmHkdfStreamingKeyManager()
    : key_factory_(absl::make_unique<AesGcmHkdfStreamingKeyFactory>()) {}

uint32_t AesGcmHkdfStreamingKeyManager::get_version() const {
  return kVersion;
}

const KeyFactory& AesGcmHkdfStreamingKeyManager::get_key_factory() const {
  return *key_factory_;
}

StatusOr<std::unique_ptr<StreamingAead>>
AesGcmHkdfStreamingKeyManager::GetPrimitiveFromKey(
    const AesGcmHkdfStreamingKey& key) const {
  Status status = Validate(key);
  if (!status.ok()) return status;
  auto streaming_result = subtle::AesGcmHkdfStreaming::New(
      key.key_value(),
      util::Enums::ProtoToSubtle(key.params().hkdf_hash_type()),
      key.params().derived_key_size(),
      key.params().ciphertext_segment_size(),
      /* first_segment_offset = */ 0);
  if (!streaming_result.ok()) return streaming_result.status();
  return {std::move(streaming_result.ValueOrDie())};
}

// static
Status AesGcmHkdfStreamingKeyManager::Validate(
    const AesGcmHkdfStreamingKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  if (key.key_value().size() < key.params().derived_key_size()) {
    return Status(util::error::INVALID_ARGUMENT,
                  "key_value (i.e. ikm) too short");
  }
  return ValidateParams(key.params());
}

// static
Status AesGcmHkdfStreamingKeyManager::Validate(
    const AesGcmHkdfStreamingKeyFormat& key_format) {
  if (key_format.key_size() <
      key_format.params().derived_key_size()) {
    return Status(util::error::INVALID_ARGUMENT,
                  "key_size must not be smaller than derived_key_size");
  }
  return ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
