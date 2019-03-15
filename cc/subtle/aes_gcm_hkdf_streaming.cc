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

#include "tink/subtle/aes_gcm_hkdf_streaming.h"

#include <string>

#include "tink/subtle/aes_gcm_hkdf_stream_segment_decrypter.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"


namespace crypto {
namespace tink {
namespace subtle {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

namespace {
Status Validate(absl::string_view ikm,
                HashType hkdf_hash,
                int derived_key_size,
                int ciphertext_segment_size,
                int first_segment_offset) {
  if (!(hkdf_hash == SHA1 || hkdf_hash == SHA256 || hkdf_hash == SHA512)) {
    return Status(util::error::INVALID_ARGUMENT, "unsupported hkdf_hash");
  }
  if (ikm.size() < 16 || ikm.size() < derived_key_size) {
    return Status(util::error::INVALID_ARGUMENT, "ikm too small");
  }
  if (derived_key_size != 16 && derived_key_size != 32) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "derived_key_size must be 16 or 32");
  }
  if (first_segment_offset < 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "first_segment_offset must be non-negative");
  }
  if (ciphertext_segment_size <
      first_segment_offset + derived_key_size) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext_segment_size too small");
  }
  return util::OkStatus();
}

}  // namespace
StatusOr<std::unique_ptr<AesGcmHkdfStreaming>>
AesGcmHkdfStreaming::New(absl::string_view ikm,
                         HashType hkdf_hash,
                         int derived_key_size,
                         int ciphertext_segment_size,
                         int first_segment_offset) {
  auto status = Validate(ikm, hkdf_hash, derived_key_size,
                         ciphertext_segment_size, first_segment_offset);
  if (!status.ok()) return status;
  std::unique_ptr<AesGcmHkdfStreaming>
      streaming_aead(new AesGcmHkdfStreaming());
  streaming_aead->ikm_ = std::string(ikm);
  streaming_aead->hkdf_hash_ = hkdf_hash;
  streaming_aead->derived_key_size_ = derived_key_size;
  streaming_aead->ciphertext_segment_size_ = ciphertext_segment_size;
  streaming_aead->first_segment_offset_ = first_segment_offset;
  return std::move(streaming_aead);
}

StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
AesGcmHkdfStreaming::NewSegmentEncrypter(
    absl::string_view associated_data) const {
  AesGcmHkdfStreamSegmentEncrypter::Params params;
  params.salt = Random::GetRandomBytes(derived_key_size_);
  auto hkdf_result = Hkdf::ComputeHkdf(
      hkdf_hash_, ikm_, params.salt, associated_data,
      derived_key_size_);
  if (!hkdf_result.ok()) return hkdf_result.status();
  params.key_value = hkdf_result.ValueOrDie();
  params.first_segment_offset = first_segment_offset_;
  params.ciphertext_segment_size = ciphertext_segment_size_;
  return AesGcmHkdfStreamSegmentEncrypter::New(params);
}

StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
AesGcmHkdfStreaming::NewSegmentDecrypter(
    absl::string_view associated_data) const {
  AesGcmHkdfStreamSegmentDecrypter::Params params;
  params.ikm = ikm_;
  params.hkdf_hash = hkdf_hash_;
  params.derived_key_size = derived_key_size_;
  params.first_segment_offset = first_segment_offset_;
  params.ciphertext_segment_size = ciphertext_segment_size_;
  params.associated_data = std::string(associated_data);
  return AesGcmHkdfStreamSegmentDecrypter::New(params);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
