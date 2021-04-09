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

#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"

#include "tink/subtle/aes_ctr_hmac_streaming.h"
#include "tink/subtle/random.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/status.h"
#include "tink/util/validation.h"

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::AesCtrHmacStreaming;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesCtrHmacStreamingKey;
using ::google::crypto::tink::AesCtrHmacStreamingKeyFormat;
using ::google::crypto::tink::AesCtrHmacStreamingParams;
using ::google::crypto::tink::HashType;

namespace {

Status ValidateParams(const AesCtrHmacStreamingParams& params) {
  if (!(params.hkdf_hash_type() == HashType::SHA1 ||
        params.hkdf_hash_type() == HashType::SHA256 ||
        params.hkdf_hash_type() == HashType::SHA512)) {
    return Status(util::error::INVALID_ARGUMENT, "unsupported hkdf_hash_type");
  }
  if (!(params.hmac_params().hash() == HashType::SHA1 ||
        params.hmac_params().hash() == HashType::SHA256 ||
        params.hmac_params().hash() == HashType::SHA512)) {
    return Status(util::error::INVALID_ARGUMENT,
                  "unsupported hmac_params.hash");
  }
  if (params.hmac_params().tag_size() < 10) {
    return Status(util::error::INVALID_ARGUMENT,
                  "hmac_params.tag_size too small");
  }
  if ((params.hmac_params().hash() == HashType::SHA1 &&
       params.hmac_params().tag_size() > 20) ||
      (params.hmac_params().hash() == HashType::SHA256 &&
       params.hmac_params().tag_size() > 32) ||
      (params.hmac_params().hash() == HashType::SHA512 &&
       params.hmac_params().tag_size() > 64)) {
    return Status(util::error::INVALID_ARGUMENT,
                  "hmac_params.tag_size too big");
  }
  int header_size = 1 + params.derived_key_size() +
      AesCtrHmacStreaming::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size() <=
      header_size + params.hmac_params().tag_size()) {
    return Status(util::error::INVALID_ARGUMENT,
                  "ciphertext_segment_size too small");
  }
  return ValidateAesKeySize(params.derived_key_size());
}

}  // namespace

crypto::tink::util::StatusOr<google::crypto::tink::AesCtrHmacStreamingKey>
AesCtrHmacStreamingKeyManager::CreateKey(
    const google::crypto::tink::AesCtrHmacStreamingKeyFormat& key_format)
    const {
  AesCtrHmacStreamingKey key;
  key.set_version(get_version());
  key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
  *key.mutable_params() = key_format.params();
  return key;
};

crypto::tink::util::StatusOr<google::crypto::tink::AesCtrHmacStreamingKey>
AesCtrHmacStreamingKeyManager::DeriveKey(
    const google::crypto::tink::AesCtrHmacStreamingKeyFormat& key_format,
    InputStream* input_stream) const {
  crypto::tink::util::Status status =
      ValidateVersion(key_format.version(), get_version());
  if (!status.ok()) return status;

  crypto::tink::util::StatusOr<std::string> randomness_or =
      ReadBytesFromStream(key_format.key_size(), input_stream);
  if (!randomness_or.ok()) {
    return randomness_or.status();
  }
  AesCtrHmacStreamingKey key;
  key.set_version(get_version());
  key.set_key_value(randomness_or.ValueOrDie());
  *key.mutable_params() = key_format.params();
  return key;
}

Status AesCtrHmacStreamingKeyManager::ValidateKey(
    const AesCtrHmacStreamingKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().size() < key.params().derived_key_size()) {
    return Status(util::error::INVALID_ARGUMENT,
                  "key_value (i.e. ikm) too short");
  }
  return ValidateParams(key.params());
}

Status AesCtrHmacStreamingKeyManager::ValidateKeyFormat(
    const AesCtrHmacStreamingKeyFormat& key_format) const {
  if (key_format.key_size() < key_format.params().derived_key_size()) {
    return Status(util::error::INVALID_ARGUMENT,
                  "key_size must not be smaller than derived_key_size");
  }
  return ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
