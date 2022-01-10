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

#include <string>

#include "absl/status/status.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"
#include "tink/subtle/random.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/validation.h"

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::AesGcmHkdfStreamSegmentEncrypter;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesGcmHkdfStreamingKey;
using ::google::crypto::tink::AesGcmHkdfStreamingKeyFormat;
using ::google::crypto::tink::AesGcmHkdfStreamingParams;
using ::google::crypto::tink::HashType;

namespace {

Status ValidateParams(const AesGcmHkdfStreamingParams& params) {
  if (!(params.hkdf_hash_type() == HashType::SHA1 ||
        params.hkdf_hash_type() == HashType::SHA256 ||
        params.hkdf_hash_type() == HashType::SHA512)) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "unsupported hkdf_hash_type");
  }
  int header_size = 1 + params.derived_key_size() +
      AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size() <=
      header_size + AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "ciphertext_segment_size too small");
  }
  return ValidateAesKeySize(params.derived_key_size());
}

}  // namespace

crypto::tink::util::StatusOr<google::crypto::tink::AesGcmHkdfStreamingKey>
AesGcmHkdfStreamingKeyManager::CreateKey(
    const google::crypto::tink::AesGcmHkdfStreamingKeyFormat& key_format)
    const {
  AesGcmHkdfStreamingKey key;
  key.set_version(get_version());
  key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
  *key.mutable_params() = key_format.params();
  return key;
};

crypto::tink::util::StatusOr<google::crypto::tink::AesGcmHkdfStreamingKey>
AesGcmHkdfStreamingKeyManager::DeriveKey(
    const google::crypto::tink::AesGcmHkdfStreamingKeyFormat& key_format,
    InputStream* input_stream) const {
  crypto::tink::util::Status status =
      ValidateVersion(key_format.version(), get_version());
  if (!status.ok()) return status;

  crypto::tink::util::StatusOr<std::string> randomness_or =
      ReadBytesFromStream(key_format.key_size(), input_stream);
  if (!randomness_or.ok()) {
    return randomness_or.status();
  }
  AesGcmHkdfStreamingKey key;
  key.set_version(get_version());
  key.set_key_value(randomness_or.ValueOrDie());
  *key.mutable_params() = key_format.params();
  return key;
}

Status AesGcmHkdfStreamingKeyManager::ValidateKey(
    const AesGcmHkdfStreamingKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().size() < key.params().derived_key_size()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "key_value (i.e. ikm) too short");
  }
  return ValidateParams(key.params());
}

Status AesGcmHkdfStreamingKeyManager::ValidateKeyFormat(
    const AesGcmHkdfStreamingKeyFormat& key_format) const {
  if (key_format.key_size() < key_format.params().derived_key_size()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "key_size must not be smaller than derived_key_size");
  }
  return ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
